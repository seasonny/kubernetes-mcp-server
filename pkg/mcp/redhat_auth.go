package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// TokenResponse represents the response from the Red Hat SSO token endpoint.
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

// getAccessToken retrieves an access token from Red Hat SSO using a refresh token.
func (s *Server) getAccessToken(ssoURL, refreshToken string) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", rhClientID)
	data.Set("refresh_token", refreshToken)

	req, err := http.NewRequest("POST", ssoURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := s.httpClient
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get access token, status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", err
	}

	return tokenResponse.AccessToken, nil
}

func getRefreshToken() (string, error) {
	// 1. Try from environment variable
	token := os.Getenv(tokenVar)
	if token != "" {
		return token, nil
	}

	// 2. Try from file in home directory
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not get user home directory: %w", err)
	}
	tokenFile := filepath.Join(home, "rh-customer-portal-token")
	content, err := os.ReadFile(tokenFile)
	if err == nil {
		return strings.TrimSpace(string(content)), nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("failed to read token file %s: %w", tokenFile, err)
	}

	// 3. If both fail, return a detailed error
	return "", fmt.Errorf("Red Hat Portal token not found. Please either set the '%s' environment variable or create a file at '%s' with your offline token. You can generate a token from https://access.redhat.com/management/api", tokenVar, tokenFile)
}
