package authclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mtgban/mtgban-website/auth"
)

// ApiResponse mirrors the auth service response structure
type ApiResponse struct {
	Success bool            `json:"success"`
	Message string          `json:"message,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// Client provides methods to interact with the auth service
type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string
}

// ClientOption is a functional option for configuring the client
type ClientOption func(*Client)

// WithTimeout sets a custom timeout for the HTTP client
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// WithToken sets the JWT token for authenticated requests
func WithToken(token string) ClientOption {
	return func(c *Client) {
		c.token = token
	}
}

// WithCustomHTTPClient sets a custom HTTP client
func WithCustomHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = client
	}
}

// NewClient creates a new auth service client
func NewClient(baseURL string, options ...ClientOption) *Client {
	client := &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	// Apply options
	for _, option := range options {
		option(client)
	}

	return client
}

// SetToken updates the JWT token for subsequent requests
func (c *Client) SetToken(token string) {
	c.token = token
}

// request is an internal helper to make HTTP requests
func (c *Client) request(ctx context.Context, method, path string, body interface{}, query url.Values) (*ApiResponse, error) {
	// Build URL
	reqURL, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	reqURL.Path = path
	reqURL.RawQuery = query.Encode()

	// Prepare request body
	var bodyReader io.Reader
	if body != nil {
		bodyData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyData)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, reqURL.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse response
	var apiResp ApiResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for API error
	if !apiResp.Success {
		return &apiResp, fmt.Errorf("API error: %s", apiResp.Error)
	}

	return &apiResp, nil
}

// HealthCheck checks if the auth service is running
func (c *Client) HealthCheck(ctx context.Context) error {
	resp, err := c.request(ctx, http.MethodGet, "/health", nil, nil)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("unhealthy service: %s", resp.Error)
	}

	return nil
}

// GetUser retrieves the current authenticated user's information
func (c *Client) GetUser(ctx context.Context) (*auth.UserData, error) {
	resp, err := c.request(ctx, http.MethodGet, "/auth/user", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	var userData auth.UserData
	if err := json.Unmarshal(resp.Data, &userData); err != nil {
		return nil, fmt.Errorf("failed to parse user data: %w", err)
	}

	return &userData, nil
}

// GetUserByID retrieves a user by their ID (admin only)
func (c *Client) GetUserByID(ctx context.Context, userID string) (*auth.UserData, error) {
	query := url.Values{}
	query.Set("id", userID)

	resp, err := c.request(ctx, http.MethodGet, "/admin/users/id", nil, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	var userData auth.UserData
	if err := json.Unmarshal(resp.Data, &userData); err != nil {
		return nil, fmt.Errorf("failed to parse user data: %w", err)
	}

	return &userData, nil
}

// GetUserFeatures retrieves the features for the authenticated user
func (c *Client) GetUserFeatures(ctx context.Context) (map[string]map[string]map[string]string, error) {
	resp, err := c.request(ctx, http.MethodGet, "/auth/features", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get user features: %w", err)
	}

	var features map[string]map[string]map[string]string
	if err := json.Unmarshal(resp.Data, &features); err != nil {
		return nil, fmt.Errorf("failed to parse features: %w", err)
	}

	return features, nil
}

// CanAccessFeature checks if the user can access a specific feature
func (c *Client) CanAccessFeature(ctx context.Context, feature auth.Feature) (bool, error) {
	query := url.Values{}
	query.Set("feature", string(feature))

	resp, err := c.request(ctx, http.MethodGet, "/auth/access/feature", nil, query)
	if err != nil {
		return false, fmt.Errorf("failed to check feature access: %w", err)
	}

	var result struct {
		HasAccess bool `json:"hasAccess"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return false, fmt.Errorf("failed to parse access result: %w", err)
	}

	return result.HasAccess, nil
}

// GetFeatureFlags retrieves all flags for a specific feature
func (c *Client) GetFeatureFlags(ctx context.Context, feature auth.Feature) (map[string]string, error) {
	query := url.Values{}
	query.Set("feature", string(feature))

	resp, err := c.request(ctx, http.MethodGet, "/auth/feature-flags", nil, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get feature flags: %w", err)
	}

	var flags map[string]string
	if err := json.Unmarshal(resp.Data, &flags); err != nil {
		return nil, fmt.Errorf("failed to parse feature flags: %w", err)
	}

	return flags, nil
}

// IsFeatureFlagEnabled checks if a specific feature flag is enabled
func (c *Client) IsFeatureFlagEnabled(ctx context.Context, feature auth.Feature, flagName string) (bool, error) {
	query := url.Values{}
	query.Set("feature", string(feature))
	query.Set("flag", flagName)

	resp, err := c.request(ctx, http.MethodGet, "/auth/feature-flag/check", nil, query)
	if err != nil {
		return false, fmt.Errorf("failed to check feature flag: %w", err)
	}

	var result struct {
		IsEnabled bool `json:"isEnabled"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return false, fmt.Errorf("failed to parse flag result: %w", err)
	}

	return result.IsEnabled, nil
}

// ForceRefreshCache forces a refresh of the auth service's cache (admin only)
func (c *Client) ForceRefreshCache(ctx context.Context) error {
	resp, err := c.request(ctx, http.MethodPost, "/admin/cache/refresh", nil, nil)
	if err != nil {
		return fmt.Errorf("failed to refresh cache: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("cache refresh failed: %s", resp.Error)
	}

	return nil
}

// GetAllUsers retrieves all users in the cache (admin only)
func (c *Client) GetAllUsers(ctx context.Context) (map[string]*auth.UserData, error) {
	resp, err := c.request(ctx, http.MethodGet, "/admin/users", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get all users: %w", err)
	}

	var users map[string]*auth.UserData
	if err := json.Unmarshal(resp.Data, &users); err != nil {
		return nil, fmt.Errorf("failed to parse users: %w", err)
	}

	return users, nil
}

// ApplyAuthVarsToPageVars applies user auth data to page variables for templates
func (c *Client) ApplyAuthVarsToPageVars(ctx context.Context, pageVars map[string]interface{}) error {
	user, err := c.GetUser(ctx)
	if err != nil {
		return fmt.Errorf("failed to get user for page vars: %w", err)
	}

	// Set basic user info
	pageVars["UserID"] = user.ID
	pageVars["UserEmail"] = user.Email
	pageVars["UserTier"] = user.Tier
	pageVars["UserRole"] = user.Role

	// Get and map feature access
	for _, feature := range auth.AllFeatures() {
		hasAccess, err := c.CanAccessFeature(ctx, feature)
		if err != nil {
			return fmt.Errorf("failed to check feature access: %w", err)
		}

		featureStr := string(feature)
		pageVars["Has"+featureStr] = hasAccess
		pageVars["Can"+featureStr] = hasAccess

		// If has access, get feature flags
		if hasAccess {
			flags, err := c.GetFeatureFlags(ctx, feature)
			if err != nil {
				return fmt.Errorf("failed to get feature flags: %w", err)
			}

			// Map flags to page vars
			for flagName, flagValue := range flags {
				pageVars[flagName] = flagValue

				// Map boolean flags with appropriate prefixes
				if auth.IsBooleanValue(flagValue) {
					boolValue := (flagValue == "true" || flagValue == "enabled" || flagValue == "yes" || flagValue == "1")

					// Convert keys based on common patterns
					if strings.HasPrefix(flagName, "Can") || strings.HasPrefix(flagName, "Is") || strings.HasPrefix(flagName, "Has") {
						prefixedKey := flagName
						pageVars[prefixedKey] = boolValue
					} else if strings.HasSuffix(flagName, "Enabled") {
						// Convert -> Enabled -> Can
						name := strings.TrimSuffix(flagName, "Enabled")
						pageVars["Can"+name] = boolValue
					} else if strings.HasSuffix(flagName, "Disabled") {
						// Convert -> Disabled -> Can (inverted)
						name := strings.TrimSuffix(flagName, "Disabled")
						pageVars["Can"+name] = !boolValue
						// Special case: if the value is "NONE", it means "enabled"
						if flagValue == "NONE" {
							pageVars["Can"+name] = true
						}
					} else {
						// Convert -> Can
						pageVars["Can"+flagName] = boolValue
					}
				}
			}
		}
	}

	return nil
}
