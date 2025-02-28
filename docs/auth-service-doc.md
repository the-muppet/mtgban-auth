# Authentication & Authorization Service Documentation

This document provides comprehensive documentation for the Authentication and Authorization Service system, including the service itself, client library, middleware components, and main server integration.

## Table of Contents

1. [Overview](#overview)
2. [Auth Service](#auth-service)
3. [Auth Client Library](#auth-client-library)
4. [Auth Middleware](#auth-middleware)
5. [Main Server Integration](#main-server-integration)
6. [Development and Deployment](#development-and-deployment)
7. [Troubleshooting](#troubleshooting)

## Overview

The Authentication and Authorization Service is a standalone microservice that handles user authentication, role-based authorization, and feature access control. It provides a RESTful API for client applications and includes a webhook mechanism for real-time updates.

### System Architecture

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│                 │      │                 │      │                 │
│   Main Server   │◄────►│   Auth Client   │◄────►│   Auth Service  │
│                 │      │                 │      │                 │
└─────────────────┘      └─────────────────┘      └─────────────────┘
         ▲                                                 ▲
         │                                                 │
         ▼                                                 ▼
┌─────────────────┐                              ┌─────────────────┐
│                 │                              │                 │
│   Web Browser   │                              │   Supabase DB   │
│                 │                              │                 │
└─────────────────┘                              └─────────────────┘
```

### Key Components

1. **Auth Service**: A standalone Go service that handles authentication, authorization, and feature access control.
2. **Auth Client Library**: A Go client library that provides methods to interact with the auth service.
3. **Auth Middleware**: Middleware components for integrating auth with the main web server.
4. **Main Server Integration**: Examples of integrating the auth system with your main application.

## Auth Service

The Auth Service is a standalone microservice that provides authentication and authorization services via a RESTful API.

### Starting the Service

```go
package main

import "yourmodule/auth"

func main() {
    // Start the auth service
    if err := auth.StartAuthService(); err != nil {
        log.Fatalf("Failed to start auth service: %v", err)
    }
}
```

### Configuration

The Auth Service is configured via environment variables:

| Variable | Description | Default |
| -------- | ----------- | ------- |
| `SUPABASE_URL` | Supabase URL | Required |
| `SUPABASE_ANON_KEY` | Supabase anonymous key | Required |
| `SUPABASE_JWT_SECRET` | Supabase JWT secret | Required |
| `REFRESH_INTERVAL` | Cache refresh interval | 24h |

### API Endpoints

#### Public Endpoints

| Endpoint | Method | Description |
| -------- | ------ | ----------- |
| `/health` | GET | Health check endpoint |

#### Auth-Protected Endpoints

| Endpoint | Method | Description |
| -------- | ------ | ----------- |
| `/auth/user` | GET | Get current user information |
| `/auth/features` | GET | Get user features |
| `/auth/access/feature?feature={featureName}` | GET | Check if user can access a feature |
| `/auth/feature-flags?feature={featureName}` | GET | Get all flags for a feature |
| `/auth/feature-flag/check?feature={featureName}&flag={flagName}` | GET | Check if a feature flag is enabled |

#### Admin-Only Endpoints

| Endpoint | Method | Description |
| -------- | ------ | ----------- |
| `/admin/cache/refresh` | POST | Force cache refresh |
| `/admin/users` | GET | Get all users |
| `/admin/users/id?id={userId}` | GET | Get user by ID |

#### Webhook Endpoints

| Endpoint | Method | Description |
| -------- | ------ | ----------- |
| `/admin/updates` | POST | Webhook for real-time updates |
| `/webhook/auth` | POST | Webhook for real-time updates |

### Response Format

All API endpoints return responses in the following JSON format:

```json
{
  "success": true,
  "message": "Optional success message",
  "data": { /* Response data */ },
  "error": "Optional error message"
}
```

## Auth Client Library

The Auth Client Library provides methods to interact with the Auth Service.

### Initialization

```go
import "yourmodule/authclient"

// Create a new auth client
client := authclient.NewClient(
    "http://auth-service:8080",
    authclient.WithTimeout(5*time.Second),
)

// Set JWT token for authenticated requests
client.SetToken("your-jwt-token")
```

### Available Methods

#### Authentication

```go
// Check if auth service is healthy
err := client.HealthCheck(ctx)

// Get current user information
user, err := client.GetUser(ctx)

// Get user by ID (admin only)
user, err := client.GetUserByID(ctx, "user-id")
```

#### Feature Access

```go
// Check if user can access a feature
hasAccess, err := client.CanAccessFeature(ctx, auth.Feature("Search"))

// Get all flags for a feature
flags, err := client.GetFeatureFlags(ctx, auth.Feature("Search"))

// Check if a feature flag is enabled
isEnabled, err := client.IsFeatureFlagEnabled(ctx, auth.Feature("Search"), "CanDownloadCSV")
```

#### Admin Operations

```go
// Force cache refresh (admin only)
err := client.ForceRefreshCache(ctx)

// Get all users (admin only)
users, err := client.GetAllUsers(ctx)
```

#### Template Helpers

```go
// Apply auth variables to page variables for templates
pageVars := make(map[string]interface{})
err := client.ApplyAuthVarsToPageVars(ctx, pageVars)
```

## Auth Middleware

The Auth Middleware provides components for integrating authentication and authorization with your main web server.

### Initialization

```go
import "yourmodule/auth/middleware"

// Initialize the auth client
InitAuthClient("http://auth-service:8080")

// Set up routes with auth middleware
mux := http.NewServeMux()
SetupRoutes(mux)
```

### Available Middleware

#### AuthMiddleware

```go
// Protect a route with authentication
mux.Handle("/dashboard", AuthMiddleware(http.HandlerFunc(DashboardHandler)))
```

The `AuthMiddleware` performs the following steps:
1. Extracts the JWT token from cookies or the Authorization header
2. Verifies the token with the auth service
3. Adds the user to the request context
4. Redirects to login if authentication fails

#### FeatureAccessMiddleware

```go
// Restrict access based on feature permissions
mux.Handle("/search", 
    AuthMiddleware(
        FeatureAccessMiddleware(auth.Search)(
            http.HandlerFunc(SearchHandler)
        )
    )
)
```

The `FeatureAccessMiddleware` performs the following steps:
1. Gets the user from the request context
2. Checks if the user can access the specified feature
3. Returns 403 Forbidden if access is denied

#### AdminOnlyMiddleware

```go
// Restrict access to admin users
mux.Handle("/admin", 
    AuthMiddleware(
        AdminOnlyMiddleware(
            http.HandlerFunc(AdminHandler)
        )
    )
)
```

The `AdminOnlyMiddleware` performs the following steps:
1. Gets the user from the request context
2. Checks if the user has the admin role
3. Returns 403 Forbidden if the user is not an admin

## Main Server Integration

The Main Server Integration provides examples of integrating the auth system with your main application.

### Server Setup

```go
func main() {
    // Initialize auth client
    authServiceURL := os.Getenv("AUTH_SERVICE_URL")
    if authServiceURL == "" {
        authServiceURL = "http://localhost:8080"
    }
    
    InitAuthClient(authServiceURL)
    
    // Check auth service health
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    if err := AuthClient.HealthCheck(ctx); err != nil {
        log.Printf("Warning: Auth service health check failed: %v", err)
    }
    
    // Set up HTTP server
    mux := http.NewServeMux()
    SetupRoutes(mux)
    
    server := &http.Server{
        Addr:    ":8000",
        Handler: mux,
    }
    
    server.ListenAndServe()
}
```

### API Integration Examples

#### User Profile API

```go
func UserProfileAPIHandler(w http.ResponseWriter, r *http.Request) {
    token := getTokenFromRequest(r)
    if token == "" {
        http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
        return
    }
    
    AuthClient.SetToken(token)
    
    ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()
    
    user, err := AuthClient.GetUser(ctx)
    if err != nil {
        http.Error(w, fmt.Sprintf(`{"error":"Failed to get user: %s"}`, err), http.StatusInternalServerError)
        return
    }
    
    // Return user data as JSON
    response := map[string]interface{}{
        "user_id": user.ID,
        "email":   user.Email,
        "tier":    user.Tier,
        "role":    user.Role,
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}
```

#### Feature Access Check API

```go
func CheckFeatureAccessHandler(w http.ResponseWriter, r *http.Request) {
    token := getTokenFromRequest(r)
    if token == "" {
        http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
        return
    }
    
    AuthClient.SetToken(token)
    
    featureName := r.URL.Query().Get("feature")
    if featureName == "" {
        http.Error(w, `{"error":"Missing feature parameter"}`, http.StatusBadRequest)
        return
    }
    
    ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()
    
    hasAccess, err := AuthClient.CanAccessFeature(ctx, auth.Feature(featureName))
    if err != nil {
        http.Error(w, fmt.Sprintf(`{"error":"Failed to check feature access: %s"}`, err), http.StatusInternalServerError)
        return
    }
    
    // Return feature access as JSON
    response := map[string]interface{}{
        "feature":    featureName,
        "has_access": hasAccess,
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}
```

### Template Integration

```go
func DashboardHandler(w http.ResponseWriter, r *http.Request) {
    ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()
    
    userObj := ctx.Value("user")
    user, ok := userObj.(*auth.UserData)
    if !ok || user == nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
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
        http.Error(w, "Error loading user features", http.StatusInternalServerError)
        return
    }
    
    // Now pageVars contains all auth-related variables:
    // - UserID, UserEmail, UserTier, UserRole
    // - HasSearch, CanDownloadCSV, etc.
    
    RenderTemplate(w, "dashboard.html", pageVars)
}
```

## Development and Deployment

### Prerequisites

- Go 1.20 or later
- Supabase account and project
- PostgreSQL database

### Local Development

1. Set up environment variables:
   ```bash
   export SUPABASE_URL=your-supabase-url
   export SUPABASE_ANON_KEY=your-supabase-anon-key
   export SUPABASE_JWT_SECRET=your-supabase-jwt-secret
   ```

2. Start the auth service:
   ```bash
   go run cmd/authservice/main.go
   ```

3. Start the main server:
   ```bash
   go run cmd/server/main.go
   ```

### Docker Deployment

#### Auth Service Dockerfile

```dockerfile
FROM golang:1.20-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o /authservice cmd/authservice/main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /authservice /app/
EXPOSE 8080
CMD ["/app/authservice"]
```

#### Docker Compose

```yaml
version: '3'
services:
  auth-service:
    build:
      context: .
      dockerfile: Dockerfile.authservice
    environment:
      - SUPABASE_URL=your-supabase-url
      - SUPABASE_ANON_KEY=your-supabase-anon-key
      - SUPABASE_JWT_SECRET=your-supabase-jwt-secret
    ports:
      - "8080:8080"
  
  main-server:
    build:
      context: .
      dockerfile: Dockerfile.mainserver
    environment:
      - AUTH_SERVICE_URL=http://auth-service:8080
    ports:
      - "8000:8000"
    depends_on:
      - auth-service
```

## Troubleshooting

### Common Issues

#### Auth Service Not Responding

If the auth service is not responding to requests:

1. Check if the service is running:
   ```bash
   curl http://localhost:8080/health
   ```

2. Check the logs for any errors:
   ```bash
   docker logs auth-service
   ```

#### Invalid JWT Token

If you're getting "Invalid token" errors:

1. Ensure your SUPABASE_JWT_SECRET is correctly set
2. Check that the token is properly formatted and not expired
3. Verify that the token is being sent in the correct format (Bearer token in Authorization header or auth_token cookie)

#### Feature Access Denied

If a user is being denied access to a feature they should have access to:

1. Check the user's role and tier in the database
2. Verify that the feature is correctly configured in the ACL
3. Check the logs for any authorization errors

### Logging

Both the auth service and the main server use structured logging to help with debugging.

To increase log verbosity, set the LOG_LEVEL environment variable:

```bash
export LOG_LEVEL=debug
```

### Support

For additional support, please contact the development team or file an issue in the project repository.