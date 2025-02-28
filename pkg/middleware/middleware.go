package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/mtgban/mtgban-website/auth"
	"github.com/the-muppet/mtgban-auth/pkg/authclient"
)

// AuthClient is a global client for the auth service
var AuthClient *authclient.Client

// InitAuthClient initializes the auth client
func InitAuthClient(baseURL string) {
	AuthClient = authclient.NewClient(
		baseURL,
		authclient.WithTimeout(5*time.Second),
	)
}

// AuthMiddleware checks if the user is authenticated
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from cookies or Authorization header
		token := getTokenFromRequest(r)

		if token == "" {
			// Redirect to login page or return unauthorized
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// Set token in client
		AuthClient.SetToken(token)

		// Create context with timeout
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Verify token by attempting to get user
		user, err := AuthClient.GetUser(ctx)
		if err != nil {
			// Token is invalid, redirect to login
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// Set user in context
		ctx = context.WithValue(ctx, auth.UserContextKey, user.ID)
		ctx = context.WithValue(ctx, "user", user)

		// Continue with the enhanced context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// FeatureAccessMiddleware restricts access to specific features
func FeatureAccessMiddleware(feature auth.Feature) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create context with timeout
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()

			// Get user from context
			userObj := ctx.Value("user")
			if userObj == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			user, ok := userObj.(*auth.UserData)
			if !ok || user == nil {
				http.Error(w, "Invalid user data", http.StatusInternalServerError)
				return
			}

			// Check feature access
			AuthClient.SetToken(getTokenFromRequest(r))
			hasAccess, err := AuthClient.CanAccessFeature(ctx, feature)
			if err != nil || !hasAccess {
				http.Error(w, "Access denied", http.StatusForbidden)
				return
			}

			// Continue with the request
			next.ServeHTTP(w, r)
		})
	}
}

// AdminOnlyMiddleware restricts access to admin users
func AdminOnlyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user from context
		ctx := r.Context()
		userObj := ctx.Value("user")
		if userObj == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		user, ok := userObj.(*auth.UserData)
		if !ok || user == nil {
			http.Error(w, "Invalid user data", http.StatusInternalServerError)
			return
		}

		// Check if user has admin role
		if user.Role == nil || *user.Role != auth.RoleAdmin {
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}

		// Continue with the request
		next.ServeHTTP(w, r)
	})
}

// Helper function to get token from request
func getTokenFromRequest(r *http.Request) string {
	// Try to get from cookie first
	cookie, err := r.Cookie("auth_token")
	if err == nil {
		return cookie.Value
	}

	// Fall back to header
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}

	return ""
}

// Setup routes with auth middleware
func SetupRoutes(mux *http.ServeMux) {
	// Public routes (no auth)
	mux.HandleFunc("/", HomeHandler)
	mux.HandleFunc("/login", LoginHandler)

	// Protected routes (require auth)
	mux.Handle("/dashboard", AuthMiddleware(http.HandlerFunc(DashboardHandler)))
	mux.Handle("/profile", AuthMiddleware(http.HandlerFunc(ProfileHandler)))

	// Feature-specific routes
	mux.Handle("/search", AuthMiddleware(FeatureAccessMiddleware(auth.Search)(http.HandlerFunc(SearchHandler))))
	mux.Handle("/newspaper", AuthMiddleware(FeatureAccessMiddleware(auth.Newspaper)(http.HandlerFunc(NewspaperHandler))))

	// Admin routes
	mux.Handle("/admin", AuthMiddleware(AdminOnlyMiddleware(http.HandlerFunc(AdminHandler))))
	mux.Handle("/admin/users", AuthMiddleware(AdminOnlyMiddleware(http.HandlerFunc(AdminUsersHandler))))
}

// Example handlers
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	// Render home page template
	RenderTemplate(w, "home.html", nil)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Process login form
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Authenticate with your backend (not shown here)
		token, err := AuthenticateUser(email, password)
		if err != nil {
			// Show error on login page
			RenderTemplate(w, "login.html", map[string]interface{}{
				"Error": "Invalid credentials",
			})
			return
		}

		// Set auth cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   3600, // 1 hour
		})

		// Redirect to dashboard
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	// Show login page
	RenderTemplate(w, "login.html", nil)
}

func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get user from context
	userObj := ctx.Value("user")
	if userObj == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	user, ok := userObj.(*auth.UserData)
	if !ok || user == nil {
		http.Error(w, "Invalid user data", http.StatusInternalServerError)
		return
	}

	// Create page variables
	pageVars := map[string]interface{}{
		"Title": "Dashboard",
		"User":  user,
	}

	// Apply auth vars to page vars
	AuthClient.SetToken(getTokenFromRequest(r))
	if err := AuthClient.ApplyAuthVarsToPageVars(ctx, pageVars); err != nil {
		// Log error but continue
		http.Error(w, "Error loading user features", http.StatusInternalServerError)
		return
	}

	// Render dashboard template
	RenderTemplate(w, "dashboard.html", pageVars)
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	// Similar to DashboardHandler but for user profile
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	userObj := ctx.Value("user")
	if userObj == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	user, ok := userObj.(*auth.UserData)
	if !ok || user == nil {
		http.Error(w, "Invalid user data", http.StatusInternalServerError)
		return
	}

	pageVars := map[string]interface{}{
		"Title": "My Profile",
		"User":  user,
	}

	AuthClient.SetToken(getTokenFromRequest(r))
	if err := AuthClient.ApplyAuthVarsToPageVars(ctx, pageVars); err != nil {
		http.Error(w, "Error loading user features", http.StatusInternalServerError)
		return
	}

	RenderTemplate(w, "profile.html", pageVars)
}

func SearchHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Create page variables
	pageVars := map[string]interface{}{
		"Title": "Search",
	}

	// Apply auth vars
	AuthClient.SetToken(getTokenFromRequest(r))
	if err := AuthClient.ApplyAuthVarsToPageVars(ctx, pageVars); err != nil {
		http.Error(w, "Error loading user features", http.StatusInternalServerError)
		return
	}

	// Add search-specific logic here

	RenderTemplate(w, "search.html", pageVars)
}

func NewspaperHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	pageVars := map[string]interface{}{
		"Title": "Newspaper",
	}

	AuthClient.SetToken(getTokenFromRequest(r))
	if err := AuthClient.ApplyAuthVarsToPageVars(ctx, pageVars); err != nil {
		http.Error(w, "Error loading user features", http.StatusInternalServerError)
		return
	}

	// Add newspaper-specific logic here

	RenderTemplate(w, "newspaper.html", pageVars)
}

func AdminHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	pageVars := map[string]interface{}{
		"Title": "Admin Dashboard",
	}

	AuthClient.SetToken(getTokenFromRequest(r))
	if err := AuthClient.ApplyAuthVarsToPageVars(ctx, pageVars); err != nil {
		http.Error(w, "Error loading user features", http.StatusInternalServerError)
		return
	}

	RenderTemplate(w, "admin/dashboard.html", pageVars)
}

func AdminUsersHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get all users (admin only)
	AuthClient.SetToken(getTokenFromRequest(r))
	users, err := AuthClient.GetAllUsers(ctx)
	if err != nil {
		http.Error(w, "Error loading users: "+err.Error(), http.StatusInternalServerError)
		return
	}

	pageVars := map[string]interface{}{
		"Title": "User Management",
		"Users": users,
	}

	if err := AuthClient.ApplyAuthVarsToPageVars(ctx, pageVars); err != nil {
		http.Error(w, "Error loading user features", http.StatusInternalServerError)
		return
	}

	RenderTemplate(w, "admin/users.html", pageVars)
}

// RenderTemplate is a helper function to render templates
func RenderTemplate(w http.ResponseWriter, tmpl string, data map[string]interface{}) {
	// Implementation depends on your templating engine
	// For example, with html/template:
	//
	// t, err := template.ParseFiles("templates/" + tmpl)
	// if err != nil {
	//     http.Error(w, err.Error(), http.StatusInternalServerError)
	//     return
	// }
	// t.Execute(w, data)
}

// AuthenticateUser is a placeholder for your authentication logic
func AuthenticateUser(email, password string) (string, error) {
	// This would be implemented with your authentication backend
	// For example, calling your auth service's login endpoint
	return "sample-jwt-token", nil
}
