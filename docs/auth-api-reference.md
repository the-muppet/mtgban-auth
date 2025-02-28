# Authentication Service API Reference

This document provides detailed information about the Authentication Service API endpoints, request/response formats, and examples.

## API Base URL

The base URL for all API endpoints is:

```
http://auth-service:8080
```

Replace `auth-service:8080` with the appropriate host and port where your auth service is running.

## Authentication

Most endpoints require authentication via a JWT token. The token should be included in the request using one of the following methods:

1. **Authorization Header**:
   ```
   Authorization: Bearer <your-jwt-token>
   ```

2. **Cookie**:
   ```
   auth_token=<your-jwt-token>
   ```

## Response Format

All API endpoints return responses in the following JSON format:

```json
{
  "success": true,
  "message": "Optional success message",
  "data": { /* Response data */ },
  "error": "Optional error message"
}
```

## Error Codes

| HTTP Code | Description |
| --------- | ----------- |
| 200 | Success |
| 400 | Bad Request - Invalid parameters or request format |
| 401 | Unauthorized - Authentication required or token invalid |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource not found |
| 500 | Internal Server Error - Unexpected server error |

## Public Endpoints

### Health Check

Check if the auth service is running properly.

**Endpoint:** `GET /health`

**Authentication Required:** No

**Example Request:**
```bash
curl -X GET http://auth-service:8080/health
```

**Example Response:**
```json
{
  "success": true,
  "message": "Auth service is healthy"
}
```

## User Authentication Endpoints

### Get Current User

Get the current authenticated user's information.

**Endpoint:** `GET /auth/user`

**Authentication Required:** Yes

**Example Request:**
```bash
curl -X GET \
  http://auth-service:8080/auth/user \
  -H 'Authorization: Bearer <your-jwt-token>'
```

**Example Response:**
```json
{
  "success": true,
  "data": {
    "id": "user123",
    "email": "user@example.com",
    "role": "admin",
    "tier": "premium",
    "status": "active",
    "features": {
      "Search": {
        "Global": {
          "CanDownloadCSV": "true",
          "CanFilterByPrice": "true"
        }
      },
      "Newspaper": {
        "Global": {
          "NewsAccess": "0day"
        }
      }
    }
  }
}
```

### Get User Features

Get all features for the current authenticated user.

**Endpoint:** `GET /auth/features`

**Authentication Required:** Yes

**Example Request:**
```bash
curl -X GET \
  http://auth-service:8080/auth/features \
  -H 'Authorization: Bearer <your-jwt-token>'
```

**Example Response:**
```json
{
  "success": true,
  "data": {
    "Search": {
      "Global": {
        "CanDownloadCSV": "true",
        "CanFilterByPrice": "true"
      }
    },
    "Newspaper": {
      "Global": {
        "NewsAccess": "0day"
      }
    }
  }
}
```

## Feature Access Endpoints

### Check Feature Access

Check if the user can access a specific feature.

**Endpoint:** `GET /auth/access/feature`

**Authentication Required:** Yes

**Query Parameters:**
- `feature` (required): The name of the feature to check

**Example Request:**
```bash
curl -X GET \
  'http://auth-service:8080/auth/access/feature?feature=Search' \
  -H 'Authorization: Bearer <your-jwt-token>'
```

**Example Response:**
```json
{
  "success": true,
  "data": {
    "hasAccess": true
  }
}
```

### Get Feature Flags

Get all flags for a specific feature.

**Endpoint:** `GET /auth/feature-flags`

**Authentication Required:** Yes

**Query Parameters:**
- `feature` (required): The name of the feature

**Example Request:**
```bash
curl -X GET \
  'http://auth-service:8080/auth/feature-flags?feature=Search' \
  -H 'Authorization: Bearer <your-jwt-token>'
```

**Example Response:**
```json
{
  "success": true,
  "data": {
    "CanDownloadCSV": "true",
    "CanFilterByPrice": "true",
    "CanFilterByPercentage": "false"
  }
}
```

### Check Feature Flag

Check if a specific feature flag is enabled.

**Endpoint:** `GET /auth/feature-flag/check`

**Authentication Required:** Yes

**Query Parameters:**
- `feature` (required): The name of the feature
- `flag` (required): The name of the flag to check

**Example Request:**
```bash
curl -X GET \
  'http://auth-service:8080/auth/feature-flag/check?feature=Search&flag=CanDownloadCSV' \
  -H 'Authorization: Bearer <your-jwt-token>'
```

**Example Response:**
```json
{
  "success": true,
  "data": {
    "isEnabled": true
  }
}
```

## Admin Endpoints

### Force Cache Refresh

Force a refresh of the auth service's cache.

**Endpoint:** `POST /admin/cache/refresh`

**Authentication Required:** Yes (Admin role required)

**Example Request:**
```bash
curl -X POST \
  http://auth-service:8080/admin/cache/refresh \
  -H 'Authorization: Bearer <your-jwt-token>'
```

**Example Response:**
```json
{
  "success": true,
  "message": "Cache refreshed successfully"
}
```

### Get All Users

Get all users in the cache.

**Endpoint:** `GET /admin/users`

**Authentication Required:** Yes (Admin role required)

**Example Request:**
```bash
curl -X GET \
  http://auth-service:8080/admin/users \
  -H 'Authorization: Bearer <your-jwt-token>'
```

**Example Response:**
```json
{
  "success": true,
  "data": {
    "user123": {
      "id": "user123",
      "email": "user@example.com",
      "role": "admin",
      "tier": "premium",
      "status": "active",
      "features": { /* ... */ }
    },
    "user456": {
      "id": "user456",
      "email": "user2@example.com",
      "role": "user",
      "tier": "free",
      "status": "active",
      "features": { /* ... */ }
    }
  }
}
```

### Get User by ID

Get a specific user by their ID.

**Endpoint:** `GET /admin/users/id`

**Authentication Required:** Yes (Admin role required)

**Query Parameters:**
- `id` (required): The user ID to look up

**Example Request:**
```bash
curl -X GET \
  'http://auth-service:8080/admin/users/id?id=user123' \
  -H 'Authorization: Bearer <your-jwt-token>'
```

**Example Response:**
```json
{
  "success": true,
  "data": {
    "id": "user123",
    "email": "user@example.com",
    "role": "admin",
    "tier": "premium",
    "status": "active",
    "features": { /* ... */ }
  }
}
```

## Webhook Endpoints

### Webhook for Updates

Receive real-time updates from the database.

**Endpoint:** `POST /admin/updates` or `POST /webhook/auth`

**Authentication Required:** Yes (Webhook secret required)

**Headers:**
- `X-Webhook-Secret` or `secret`: The webhook secret key

**Example Request:**
```bash
curl -X POST \
  http://auth-service:8080/webhook/auth \
  -H 'Content-Type: application/json' \
  -H 'X-Webhook-Secret: <your-webhook-secret>' \
  -d '{
    "type": "INSERT",
    "table": "active_subscribers",
    "record": {
      "uuid": "user789",
      "email": "new-user@example.com",
      "tier": "premium",
      "status": "active"
    }
  }'
```

**Example Response:**
```json
{
  "success": true
}
```

## Client SDK Examples

### Go Client

```go
import (
    "context"
    "github.com/the-muppet/mtgban-auth/authclient"
)

func main() {
    // Create client
    client := authclient.NewClient("http://auth-service:8080")
    client.SetToken("your-jwt-token")
    
    ctx := context.Background()
    
    // Get user
    user, err := client.GetUser(ctx)
    if err != nil {
        // Handle error
    }
    
    // Check feature access
    hasAccess, err := client.CanAccessFeature(ctx, "Search")
    if err != nil {
        // Handle error
    }
    
    // Get feature flags
    flags, err := client.GetFeatureFlags(ctx, "Search")
    if err != nil {
        // Handle error
    }
}
```

### JavaScript/TypeScript Client

While not implemented in this package, here's how you might use the API with fetch:

```javascript
// Create an auth client
class AuthClient {
  constructor(baseUrl, token) {
    this.baseUrl = baseUrl;
    this.token = token;
  }
  
  async request(path, options = {}) {
    const url = `${this.baseUrl}${path}`;
    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.token}`,
      ...options.headers
    };
    
    const response = await fetch(url, {
      ...options,
      headers
    });
    
    const data = await response.json();
    
    if (!data.success) {
      throw new Error(data.error || 'Request failed');
    }
    
    return data.data;
  }
  
  async getUser() {
    return this.request('/auth/user');
  }
  
  async canAccessFeature(feature) {
    return this.request(`/auth/access/feature?feature=${feature}`);
  }
  
  async getFeatureFlags(feature) {
    return this.request(`/auth/feature-flags?feature=${feature}`);
  }
}

// Usage
const client = new AuthClient('http://auth-service:8080', 'your-jwt-token');

// Get user
client.getUser()
  .then(user => console.log(user))
  .catch(err => console.error(err));

// Check feature access
client.canAccessFeature('Search')
  .then(result => console.log(result.hasAccess))
  .catch(err => console.error(err));
```

## Rate Limits

The auth service enforces the following rate limits:

- Public endpoints: 60 requests per minute per IP
- Authenticated endpoints: 300 requests per minute per user
- Admin endpoints: 120 requests per minute per admin user

When rate limits are exceeded, the service returns a 429 Too Many Requests response.

## Feature Definitions

Here are the available features and their flags:

### Search Feature

| Flag | Description | Values |
| ---- | ----------- | ------ |
| `CanDownloadCSV` | Whether the user can download search results as CSV | `true`/`false` |
| `CanFilterByPrice` | Whether the user can filter search results by price | `true`/`false` |
| `CanFilterByPercentage` | Whether the user can filter search results by percentage | `true`/`false` |
| `ShowSealedYP` | Whether to show sealed yield percentage | `true`/`false` |

### Newspaper Feature

| Flag | Description | Values |
| ---- | ----------- | ------ |
| `NewsAccess` | The user's news access level | `0day`, `1day`, `3day` |
| `CanSwitchDay` | Whether the user can switch between days | `true`/`false` |

### Upload Feature

| Flag | Description | Values |
| ---- | ----------- | ------ |
| `CanBuylist` | Whether the user can create buy lists | `true`/`false` |
| `CanChangeStores` | Whether the user can change stores | `true`/`false` |
| `HasOptimizer` | Whether the user has access to the optimizer | `true`/`false` |
| `NoUploadLimit` | Whether the user has no upload limit | `true`/`false` |

## Security Considerations

- Always use HTTPS in production environments
- Keep JWT tokens secure and use short expiration times
- Implement proper token refresh mechanisms
- Store sensitive information (like webhook secrets) in secure environment variables or secret management systems
- Regularly rotate secrets and keys
