# Auth Service

A standalone authentication and authorization service with feature access control for Go applications.

## Overview

This package provides a complete authentication and authorization solution that can run as a standalone microservice or be embedded within your application.  
It handles user authentication, role-based authorization, feature flags, and access control.

Key features:
- JWT-based authentication
- Role-based access control
- Feature flags management
- Subscription tier management
- Real-time updates via webhooks
- Caching for performance

## Quick Links

- [Quick Start](docs/auth-quickstart-guide.md) - Get up and running quickly
- [ElmoAuth Service Documentation](docs/auth-service-doc.md) - Full system documentation
- [ElmoAuth Service Endpoints](docs/auth-api-reference.md) - Detailed API documentation

## Installation

```bash
go get github.com/the-muppet/mtgban-auth
```

## Basic Usage

### Starting the Auth Service

```go
package main

import "github.com/the-muppet/mtgban-auth/auth"

func main() {
    if err := auth.StartAuthService(); err != nil {
        log.Fatalf("Failed to start auth service: %v", err)
    }
}
```

### Using the Client Library

```go
import "github.com/yourusername/auth-service/authclient"

// Create client
client := authclient.NewClient("http://auth-service:8080")
client.SetToken(jwtToken)

// Check if user can access a feature
hasAccess, err := client.CanAccessFeature(ctx, auth.Feature("Search"))
```

### Using the Middleware

```go
import "github.com/the-muppet/mtgban-auth/middleware"

// Protect routes with authentication
mux.Handle("/dashboard", AuthMiddleware(http.HandlerFunc(DashboardHandler)))

// Restrict access by feature
mux.Handle("/search", 
    AuthMiddleware(
        FeatureAccessMiddleware(auth.Search)(
            http.HandlerFunc(SearchHandler)
        )
    )
)
```

## Configuration

The service is configured via environment variables:

```
SUPABASE_URL=your-supabase-url
SUPABASE_ANON_KEY=your-supabase-anon-key
SUPABASE_JWT_SECRET=your-supabase-jwt-secret
REFRESH_INTERVAL=24h
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

For more detailed information, refer to:
- [Authentication Service Documentation](./docs/auth-service-doc.md)
- [Authentication Service API Reference](./docs/auth-api-reference.md)
- [Authentication Service Quick Start Guide](./docs/auth-quickstart-guide.md)


