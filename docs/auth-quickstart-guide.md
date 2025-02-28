# Authentication Service Quick Start Guide

This guide will help you get started with the Authentication Service, quickly set up the service, and integrate it with your main application.

## Prerequisites

- Go 1.20 or later
- Supabase account and project
- Docker (optional, for containerized deployment)

## Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/auth-service.git
cd auth-service
```

## Step 2: Set Up Environment Variables

Create a `.env` file with the following variables:

```
SUPABASE_URL=your-supabase-url
SUPABASE_ANON_KEY=your-supabase-anon-key
SUPABASE_JWT_SECRET=your-supabase-jwt-secret
REFRESH_INTERVAL=24h
```

Load these environment variables:

```bash
source .env
```

## Step 3: Run the Auth Service

### Option 1: Run directly with Go

```bash
go run cmd/authservice/main.go
```

### Option 2: Build and run the binary

```bash
go build -o authservice cmd/authservice/main.go
./authservice
```

### Option 3: Run with Docker

```bash
docker build -t auth-service -f Dockerfile.authservice .
docker run -p 8080:8080 --env-file .env auth-service
```

The auth service should now be running on port 8080. You can test it with:

```bash
curl http://localhost:8080/health
```

Expected output:
```json
{"success":true,"message":"Auth service is healthy"}
```

## Step 4: Set Up the Main Server

Create a new Go file for your main server (e.g., `main.go`):

```go
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/the-muppet/mtgban-auth/authclient"
)

// Initialize the global auth client
var AuthClient *authclient.Client

func main() {
	// Set auth service URL
	authServiceURL := os.Getenv("AUTH_SERVICE_URL")
	if authServiceURL == "" {
		authServiceURL = "http://localhost:8080"
	}

	// Initialize the auth client
	AuthClient = authclient.NewClient(
		authServiceURL,
		authclient.WithTimeout(5*time.Second),
	)

	// Check if auth service is available
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := AuthClient.HealthCheck(ctx); err != nil {
		log.Printf("Warning: Auth service health check failed: %v", err)
		log.Printf("Continuing startup, but auth features may not work")
	} else {
		log.Printf("Auth service health check successful")
	}

	// Set up HTTP server
	mux := http.NewServeMux()
	
	// Public routes (no auth)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Welcome to the main server!"))
	})
	
	// Protected routes (require auth)
	mux.Handle("/dashboard", AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Protected dashboard page"))
	})))
	
	// Feature-specific routes
	mux.Handle("/search", AuthMiddleware(FeatureAccessMiddleware("Search")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Search feature page"))
	}))))
	
	// Start the server
	log.Println("Starting main server on :8000")
	if err := http.ListenAndServe(":8000", mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
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
		
		// Add user to context
		ctx = context.WithValue(ctx, "user", user)
		
		// Continue with the enhanced context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// FeatureAccessMiddleware restricts access to specific features
func FeatureAccessMiddleware(feature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create context with timeout
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			
			// Get user from context
			user, ok := ctx.Value("user").(*auth.UserData)
			if !ok || user == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			
			// Check feature access
			hasAccess, err := AuthClient.CanAccessFeature(ctx, auth.Feature(feature))
			if err != nil || !hasAccess {
				http.Error(w, "Access denied", http.StatusForbidden)
				return
			}
			
			// Continue with the request
			next.ServeHTTP(w, r)
		})
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
```

## Step 5: Implement User Authentication Flow

### Create a Login Handler

Add a login handler to your main server:

```go
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Get form values
		email := r.FormValue("email")
		password := r.FormValue("password")
		
		// This is a placeholder for your actual authentication logic
		// In a real application, you would verify credentials against your database
		token, err := authenticate(email, password)
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		
		// Set token as cookie
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
	
	// Show login form for GET requests
	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Login</title>
	</head>
	<body>
		<h1>Login</h1>
		<form method="post" action="/login">
			<div>
				<label>Email:</label>
				<input type="email" name="email" required>
			</div>
			<div>
				<label>Password:</label>
				<input type="password" name="password" required>
			</div>
			<div>
				<button type="submit">Login</button>
			</div>
		</form>
	</body>
	</html>
	`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// authenticate is a placeholder for your actual authentication logic
func authenticate(email, password string) (string, error) {
	// In a real application, you would verify credentials with your auth backend
	// and get a JWT token
	
	// For testing purposes, always return a valid token
	// DO NOT USE THIS IN PRODUCTION
	return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIn0.dummySignature", nil
}
```

Add the login handler to your routes:

```go
// Add this to your route setup in main()
mux.HandleFunc("/login", LoginHandler)
```

## Step 6: Create a Dashboard Page with Feature Access Checks

```go
func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	ctx := r.Context()
	user, ok := ctx.Value("user").(*auth.UserData)
	if !ok || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// Check access to specific features
	AuthClient.SetToken(getTokenFromRequest(r))
	
	canAccessSearch, _ := AuthClient.CanAccessFeature(ctx, auth.Feature("Search"))
	canAccessNewspaper, _ := AuthClient.CanAccessFeature(ctx, auth.Feature("Newspaper"))
	
	// Build HTML response with feature access info
	html := fmt.Sprintf(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>Dashboard</title>
	</head>
	<body>
		<h1>Welcome, %s!</h1>
		<p>Your subscription tier: %s</p>
		
		<h2>Your Features:</h2>
		<ul>
			<li>Search Feature: %s</li>
			<li>Newspaper Feature: %s</li>
		</ul>
		
		<h2>Available Pages:</h2>
		<ul>
			%s
			%s
		</ul>
		
		<p><a href="/logout">Logout</a></p>
	</body>
	</html>
	`,
		user.Email,
		user.Tier,
		accessStatus(canAccessSearch),
		accessStatus(canAccessNewspaper),
		featureLink(canAccessSearch, "/search", "Search Page"),
		featureLink(canAccessNewspaper, "/newspaper", "Newspaper Page"),
	)
	
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// Helper function to show access status
func accessStatus(hasAccess bool) string {
	if hasAccess {
		return "✅ Enabled"
	}
	return "❌ Disabled"
}

// Helper function to create feature links
func featureLink(hasAccess bool, url, text string) string {
	if hasAccess {
		return fmt.Sprintf(`<li><a href="%s">%s</a></li>`, url, text)
	}
	return fmt.Sprintf(`<li>%s (Upgrade to access)</li>`, text)
}
```

Update your routes to use the new dashboard handler:

```go
// Update this in your route setup in main()
mux.Handle("/dashboard", AuthMiddleware(http.HandlerFunc(DashboardHandler)))
```

## Step 7: Add a Logout Handler

```go
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Clear the auth cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // Delete the cookie
	})
	
	// Redirect to home page
	http.Redirect(w, r, "/", http.StatusFound)
}
```

Add the logout handler to your routes:

```go
// Add this to your route setup in main()
mux.HandleFunc("/logout", LogoutHandler)
```

## Step 8: Add Feature-Specific Pages

### Search Page Example

```go
func SearchHandler(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	ctx := r.Context()
	user, ok := ctx.Value("user").(*auth.UserData)
	if !ok || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// Get search-specific feature flags
	AuthClient.SetToken(getTokenFromRequest(r))
	flags, err := AuthClient.GetFeatureFlags(ctx, auth.Feature("Search"))
	if err != nil {
		http.Error(w, "Error loading feature flags", http.StatusInternalServerError)
		return
	}
	
	// Check specific flags
	canDownloadCSV := flags["CanDownloadCSV"] == "true"
	canFilterByPrice := flags["CanFilterByPrice"] == "true"
	
	// Build HTML response with feature flags info
	html := fmt.Sprintf(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>Search</title>
	</head>
	<body>
		<h1>Search Page</h1>
		
		<form method="get" action="/search">
			<input type="text" name="q" placeholder="Search...">
			
			%s
			
			<button type="submit">Search</button>
		</form>
		
		<div>
			<h2>Search Results</h2>
			<!-- Search results would go here -->
			<p>No results to display.</p>
			
			%s
		</div>
		
		<p><a href="/dashboard">Back to Dashboard</a></p>
	</body>
	</html>
	`,
		priceFilterHTML(canFilterByPrice),
		downloadButtonHTML(canDownloadCSV),
	)
	
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// Helper function for price filter HTML
func priceFilterHTML(canFilterByPrice bool) string {
	if canFilterByPrice {
		return `
		<div>
			<label>Price Range:</label>
			<input type="number" name="min_price" placeholder="Min" min="0">
			<input type="number" name="max_price" placeholder="Max" min="0">
		</div>
		`
	}
	return ""
}

// Helper function for download button HTML
func downloadButtonHTML(canDownloadCSV bool) string {
	if canDownloadCSV {
		return `<p><button type="button">Download as CSV</button></p>`
	}
	return `<p><em>Upgrade your plan to download results as CSV</em></p>`
}
```

Update your routes to use the new search handler:

```go
// Update this in your route setup in main()
mux.Handle("/search", AuthMiddleware(FeatureAccessMiddleware("Search")(http.HandlerFunc(SearchHandler))))
```

## Step 9: Testing the Integration

1. Start the auth service:
   ```bash
   go run cmd/authservice/main.go
   ```

2. In a separate terminal, start the main server:
   ```bash
   go run main.go
   ```

3. Open your browser and navigate to:
   ```
   http://localhost:8000/login
   ```

4. Log in with your test credentials.

5. After successful login, you should be redirected to the dashboard, which shows your features and available pages.

