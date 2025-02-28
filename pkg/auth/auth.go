package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// API response structure
type ApiResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// JWT claims structure
type AuthClaims struct {
	UserID string `json:"sub"`
	Email  string `json:"email,omitempty"`
	jwt.RegisteredClaims
}

// InitAuthService creates and initializes an AuthService with sensible defaults
func InitAuthService(config *AuthConfig, client SupabaseClient, logger *log.Logger) (*AuthService, error) {
	var err error

	// Set up logger if not provided
	if logger == nil {
		logger = log.New(os.Stdout, "[AUTH] ", log.LstdFlags)
		logger.Printf("No logger provided, using default")
	}

	// Load or validate config
	if config == nil {
		logger.Printf("No auth config provided, loading default from env")
		config, err = LoadDefaultAuthConfig()
		if err != nil {
			logger.Printf("Failed to load default auth config: %v", err)
			return nil, fmt.Errorf("failed to load auth config: %w", err)
		}
	}

	if err := config.validate(); err != nil {
		logger.Printf("Failed to validate auth config: %v", err)
		return nil, fmt.Errorf("invalid auth config: %w", err)
	}

	// Initialize Supabase client if not provided
	if client == nil {
		logger.Printf("No supabase client provided, initializing from config")
		client, err = InitSupabaseClient(config.SBase.SupabaseURL, config.SBase.SupabaseKey)
		if err != nil {
			logger.Printf("Failed to initialize supabase client: %v", err)
			return nil, fmt.Errorf("failed to init supabase client: %w", err)
		}
	}

	// Set default refresh interval if not specified
	if config.SBase.RefreshInterval == 0 {
		config.SBase.RefreshInterval = 24 * time.Hour
		logger.Printf("Using default refresh interval of %v", config.SBase.RefreshInterval)
	}

	// Create user repository
	repo, err := NewSupabaseUserRepository(client, logger)
	if err != nil {
		logger.Printf("Failed to create user repository: %v", err)
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}

	// Set up cache options
	cacheOpts := DefaultCacheOptions()
	cacheOpts.Logger = logger

	// Create cache
	cache := NewCache(cacheOpts)

	// Create the auth service with all components
	authService, err := NewAuthService(
		client,
		config,
		WithLogger(logger),
		WithRepository(repo),
		WithCache(cache),
	)

	if err != nil {
		logger.Printf("Failed to create auth service: %v", err)
		return nil, fmt.Errorf("failed to create auth service: %w", err)
	}

	// Initialize cache data
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	err = authService.cache.LoadInitialData(ctx, repo)
	if err != nil {
		logger.Printf("Warning: could not load initial user data: %v", err)
	} else {
		logger.Printf("Successfully loaded initial user data")
	}

	return authService, nil
}

// Helper function to send JSON responses
func sendResponse(w http.ResponseWriter, response ApiResponse, statusCode int) {
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// Helper function to send error responses
func sendErrorResponse(w http.ResponseWriter, errorMsg string, statusCode int) {
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ApiResponse{
		Success: false,
		Error:   errorMsg,
	})
}

// GetCache returns the user cache from the auth service
func (s *AuthService) GetCache() *UserCache {
	return s.cache
}

// GetRepo returns the user repository from the auth service
func (s *AuthService) GetRepo() *UserRepo {
	return &s.repo
}

// RegisterShutdownHandler registers a signal handler to gracefully shut down the service
func (s *AuthService) RegisterShutdownHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		// Create a context with timeout for shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.Shutdown(ctx); err != nil {
			s.logger.Printf("Error during shutdown: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}()
}

// IsFeatureEnabled checks if a specific feature flag is enabled for a user
func (s *AuthService) IsFeatureEnabled(user *UserData, feature Feature, flagName string) bool {
	if user == nil || user.Features == nil {
		return false
	}

	// Check if user has access to the feature
	if !s.CanAccessFeature(user, feature) {
		return false
	}

	// Check if the feature flag exists
	featureStr := string(feature)
	for category, features := range user.Features {
		if strings.EqualFold(category, featureStr) {
			for _, settings := range features {
				if value, exists := settings[flagName]; exists {
					return value == "true" || value == "enabled" || value == "yes" || value == "1"
				}
			}
		}
	}

	return false
}

// StartAuthService initializes and starts the auth service with HTTP endpoints
func StartAuthService() error {
	logger := log.New(os.Stdout, "[AUTH-SERVICE] ", log.LstdFlags)

	// Initialize the auth service
	authService, err := InitAuthService(nil, nil, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize auth service: %w", err)
	}

	// Get JWT secret from config or environment
	jwtSecret := authService.config.SBase.SupabaseSecret
	if jwtSecret == "" {
		jwtSecret = os.Getenv("SUPABASE_JWT_SECRET")
		if jwtSecret == "" {
			return errors.New("JWT secret not configured")
		}
	}

	// Set up HTTP handlers
	mux := http.NewServeMux()

	// Middleware for logging and response headers
	loggingMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			w.Header().Set("Content-Type", "application/json")

			next.ServeHTTP(w, r)

			logger.Printf("%s %s %s %s", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start))
		})
	}

	// Middleware to extract and validate JWT tokens
	authMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				sendErrorResponse(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			// Extract the token
			tokenParts := strings.Split(authHeader, " ")
			if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
				sendErrorResponse(w, "Invalid authorization format, use 'Bearer {token}'", http.StatusUnauthorized)
				return
			}

			tokenString := tokenParts[1]

			// Parse and validate token
			token, err := jwt.ParseWithClaims(tokenString, &AuthClaims{}, func(token *jwt.Token) (interface{}, error) {
				return []byte(jwtSecret), nil
			})

			if err != nil {
				sendErrorResponse(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(*AuthClaims)
			if !ok || !token.Valid {
				sendErrorResponse(w, "Invalid token claims", http.StatusUnauthorized)
				return
			}

			// Add user ID to request context
			ctx := context.WithValue(r.Context(), UserContextKey, claims.UserID)

			// Continue with the enhanced context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	// Add routes with appropriate middleware

	// Public endpoints (no auth required)
	mux.Handle("/health", loggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sendResponse(w, ApiResponse{Success: true, Message: "Auth service is healthy"}, http.StatusOK)
	})))

	// Auth-protected endpoints

	// 1. User information endpoint
	mux.Handle("/auth/user", loggingMiddleware(authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		userID, ok := ctx.Value(UserContextKey).(string)
		if !ok || userID == "" {
			sendErrorResponse(w, "User ID not found in context", http.StatusInternalServerError)
			return
		}

		userData, err := authService.GetUserByID(ctx, userID)
		if err != nil {
			sendErrorResponse(w, "Failed to get user: "+err.Error(), http.StatusNotFound)
			return
		}

		sendResponse(w, ApiResponse{Success: true, Data: userData}, http.StatusOK)
	}))))

	// 2. User features endpoint
	mux.Handle("/auth/features", loggingMiddleware(authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		userID, ok := ctx.Value(UserContextKey).(string)
		if !ok || userID == "" {
			sendErrorResponse(w, "User ID not found in context", http.StatusInternalServerError)
			return
		}

		features, err := authService.GetUserFeatures(ctx, userID)
		if err != nil {
			sendErrorResponse(w, "Failed to get user features: "+err.Error(), http.StatusInternalServerError)
			return
		}

		sendResponse(w, ApiResponse{Success: true, Data: features}, http.StatusOK)
	}))))

	// 3. Feature access check endpoint
	mux.Handle("/auth/access/feature", loggingMiddleware(authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		userID, ok := ctx.Value(UserContextKey).(string)
		if !ok || userID == "" {
			sendErrorResponse(w, "User ID not found in context", http.StatusInternalServerError)
			return
		}

		featureName := r.URL.Query().Get("feature")
		if featureName == "" {
			sendErrorResponse(w, "Feature parameter required", http.StatusBadRequest)
			return
		}

		user, err := authService.GetUserByID(ctx, userID)
		if err != nil {
			sendErrorResponse(w, "Failed to get user: "+err.Error(), http.StatusInternalServerError)
			return
		}

		hasAccess := authService.CanAccessFeature(user, Feature(featureName))

		sendResponse(w, ApiResponse{
			Success: true,
			Data: map[string]bool{
				"hasAccess": hasAccess,
			},
		}, http.StatusOK)
	}))))

	// 4. Feature flags endpoint
	mux.Handle("/auth/feature-flags", loggingMiddleware(authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		userID, ok := ctx.Value(UserContextKey).(string)
		if !ok || userID == "" {
			sendErrorResponse(w, "User ID not found in context", http.StatusInternalServerError)
			return
		}

		featureName := r.URL.Query().Get("feature")
		if featureName == "" {
			sendErrorResponse(w, "Feature parameter required", http.StatusBadRequest)
			return
		}

		user, err := authService.GetUserByID(ctx, userID)
		if err != nil {
			sendErrorResponse(w, "Failed to get user: "+err.Error(), http.StatusInternalServerError)
			return
		}

		features, err := authService.GetUserFeatures(ctx, userID)
		if err != nil {
			sendErrorResponse(w, "Failed to get user features: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Extract flags for the specific feature
		featureFlags := make(map[string]string)
		for category, featureMap := range features {
			if strings.EqualFold(category, featureName) {
				for _, flags := range featureMap {
					for flag, value := range flags {
						featureFlags[flag] = value
					}
				}
			}
		}

		sendResponse(w, ApiResponse{Success: true, Data: featureFlags}, http.StatusOK)
	}))))

	// 5. Feature flag check endpoint
	mux.Handle("/auth/feature-flag/check", loggingMiddleware(authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		userID, ok := ctx.Value(UserContextKey).(string)
		if !ok || userID == "" {
			sendErrorResponse(w, "User ID not found in context", http.StatusInternalServerError)
			return
		}

		featureName := r.URL.Query().Get("feature")
		flagName := r.URL.Query().Get("flag")

		if featureName == "" || flagName == "" {
			sendErrorResponse(w, "Feature and flag parameters required", http.StatusBadRequest)
			return
		}

		user, err := authService.GetUserByID(ctx, userID)
		if err != nil {
			sendErrorResponse(w, "Failed to get user: "+err.Error(), http.StatusInternalServerError)
			return
		}

		isEnabled := authService.IsFeatureEnabled(user, Feature(featureName), flagName)

		sendResponse(w, ApiResponse{
			Success: true,
			Data: map[string]bool{
				"isEnabled": isEnabled,
			},
		}, http.StatusOK)
	}))))

	// Admin endpoints (requires admin role)

	// 6. Force cache refresh endpoint (admin only)
	mux.Handle("/admin/cache/refresh", loggingMiddleware(authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()

		userID, ok := ctx.Value(UserContextKey).(string)
		if !ok || userID == "" {
			sendErrorResponse(w, "User ID not found in context", http.StatusInternalServerError)
			return
		}

		user, err := authService.GetUserByID(ctx, userID)
		if err != nil {
			sendErrorResponse(w, "Failed to get user: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Check if user has admin role
		if user.Role == nil || *user.Role != RoleAdmin {
			sendErrorResponse(w, "Admin access required", http.StatusForbidden)
			return
		}

		err = authService.RefreshCache(ctx)
		if err != nil {
			sendErrorResponse(w, "Failed to refresh cache: "+err.Error(), http.StatusInternalServerError)
			return
		}

		sendResponse(w, ApiResponse{Success: true, Message: "Cache refreshed successfully"}, http.StatusOK)
	}))))

	// 7. Get all users endpoint (admin only)
	mux.Handle("/admin/users", loggingMiddleware(authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		userID, ok := ctx.Value(UserContextKey).(string)
		if !ok || userID == "" {
			sendErrorResponse(w, "User ID not found in context", http.StatusInternalServerError)
			return
		}

		user, err := authService.GetUserByID(ctx, userID)
		if err != nil {
			sendErrorResponse(w, "Failed to get user: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Check if user has admin role
		if user.Role == nil || *user.Role != RoleAdmin {
			sendErrorResponse(w, "Admin access required", http.StatusForbidden)
			return
		}

		users := authService.cache.GetAllUsers()

		sendResponse(w, ApiResponse{Success: true, Data: users}, http.StatusOK)
	}))))

	// 8. Get user by ID endpoint (admin only)
	mux.Handle("/admin/users/id", loggingMiddleware(authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		adminID, ok := ctx.Value(UserContextKey).(string)
		if !ok || adminID == "" {
			sendErrorResponse(w, "User ID not found in context", http.StatusInternalServerError)
			return
		}

		admin, err := authService.GetUserByID(ctx, adminID)
		if err != nil {
			sendErrorResponse(w, "Failed to get admin user: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Check if user has admin role
		if admin.Role == nil || *admin.Role != RoleAdmin {
			sendErrorResponse(w, "Admin access required", http.StatusForbidden)
			return
		}

		// Get the requested user ID
		targetUserID := r.URL.Query().Get("id")
		if targetUserID == "" {
			sendErrorResponse(w, "Missing id parameter", http.StatusBadRequest)
			return
		}

		userData, err := authService.GetUserByID(ctx, targetUserID)
		if err != nil {
			sendErrorResponse(w, "Failed to get user: "+err.Error(), http.StatusNotFound)
			return
		}

		sendResponse(w, ApiResponse{Success: true, Data: userData}, http.StatusOK)
	}))))

	// Add webhook handler for real-time updates
	RegisterWebhookHandlers(mux, authService)

	// Register shutdown handler
	authService.RegisterShutdownHandler()

	// Create HTTP server with reasonable timeouts
	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 20 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start HTTP server
	logger.Printf("Starting auth service on port 8080")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// RunAuthService is a simple entry point to run the auth service
func RunAuthService() {
	if err := StartAuthService(); err != nil {
		log.Fatalf("Auth service error: %v", err)
	}
}
