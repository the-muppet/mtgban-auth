package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// Set up logging
	logger := log.New(os.Stdout, "[MAIN-SERVER] ", log.LstdFlags)

	// Initialize auth client
	authServiceURL := os.Getenv("AUTH_SERVICE_URL")
	if authServiceURL == "" {
		authServiceURL = "http://localhost:8080" // Default to localhost if not specified
	}

	logger.Printf("Initializing auth client with service URL: %s", authServiceURL)
	InitAuthClient(authServiceURL)

	// Check if auth service is available
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := AuthClient.HealthCheck(ctx)
	if err != nil {
		logger.Printf("Warning: Auth service health check failed: %v", err)
		logger.Printf("Continuing startup, but auth features may not work")
	} else {
		logger.Printf("Auth service health check successful")
	}

	// Create HTTP server
	mux := http.NewServeMux()
	SetupRoutes(mux)

	// Set up HTTP server with reasonable timeouts
	server := &http.Server{
		Addr:         ":8000",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 20 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start HTTP server in background
	go func() {
		logger.Printf("Starting server on port 8000")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	logger.Printf("Shutting down server...")

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Shutdown HTTP server
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Fatalf("Server shutdown error: %v", err)
	}

	logger.Printf("Server shutdown complete")
}

// The following functions are examples of handlers for the main server
// and demonstrate how to integrate with the auth service

// UserProfileAPIHandler provides user profile data via API
func UserProfileAPIHandler(w http.ResponseWriter, r *http.Request) {
	// Extract token from request
	token := getTokenFromRequest(r)
	if token == "" {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Set token in auth client
	AuthClient.SetToken(token)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get user data from auth service
	user, err := AuthClient.GetUser(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Failed to get user: %s"}`, err), http.StatusInternalServerError)
		return
	}

	// Map features to a simplified format
	features, err := AuthClient.GetUserFeatures(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Failed to get features: %s"}`, err), http.StatusInternalServerError)
		return
	}

	// Create response with user data and features
	response := map[string]interface{}{
		"user_id":  user.ID,
		"email":    user.Email,
		"tier":     user.Tier,
		"role":     user.Role,
		"features": features,
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")

	// Return response
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Failed to encode response: %s"}`, err), http.StatusInternalServerError)
		return
	}
}

// CheckFeatureAccessHandler provides an API endpoint to check feature access
func CheckFeatureAccessHandler(w http.ResponseWriter, r *http.Request) {
	// Extract token
	token := getTokenFromRequest(r)
	if token == "" {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Set token in auth client
	AuthClient.SetToken(token)

	// Get feature name from query string
	featureName := r.URL.Query().Get("feature")
	if featureName == "" {
		http.Error(w, `{"error":"Missing feature parameter"}`, http.StatusBadRequest)
		return
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Check feature access
	hasAccess, err := AuthClient.CanAccessFeature(ctx, auth.Feature(featureName))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Failed to check feature access: %s"}`, err), http.StatusInternalServerError)
		return
	}

	// Create response
	response := map[string]interface{}{
		"feature":    featureName,
		"has_access": hasAccess,
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")

	// Return response
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Failed to encode response: %s"}`, err), http.StatusInternalServerError)
		return
	}
}

// GetFeatureFlagsHandler provides an API endpoint to get feature flags
func GetFeatureFlagsHandler(w http.ResponseWriter, r *http.Request) {
	// Extract token
	token := getTokenFromRequest(r)
	if token == "" {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Set token in auth client
	AuthClient.SetToken(token)

	// Get feature name from query string
	featureName := r.URL.Query().Get("feature")
	if featureName == "" {
		http.Error(w, `{"error":"Missing feature parameter"}`, http.StatusBadRequest)
		return
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get feature flags
	flags, err := AuthClient.GetFeatureFlags(ctx, auth.Feature(featureName))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Failed to get feature flags: %s"}`, err), http.StatusInternalServerError)
		return
	}

	// Create response
	response := map[string]interface{}{
		"feature": featureName,
		"flags":   flags,
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")

	// Return response
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Failed to encode response: %s"}`, err), http.StatusInternalServerError)
		return
	}
}

// ForceRefreshCacheHandler provides an admin API endpoint to force refresh the auth cache
func ForceRefreshCacheHandler(w http.ResponseWriter, r *http.Request) {
	// Extract token
	token := getTokenFromRequest(r)
	if token == "" {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Set token in auth client
	AuthClient.SetToken(token)

	// Create context with timeout (this operation might take longer)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Force refresh cache
	err := AuthClient.ForceRefreshCache(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Failed to refresh cache: %s"}`, err), http.StatusInternalServerError)
		return
	}

	// Create success response
	response := map[string]interface{}{
		"success": true,
		"message": "Cache refreshed successfully",
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")

	// Return response
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Failed to encode response: %s"}`, err), http.StatusInternalServerError)
		return
	}
}
