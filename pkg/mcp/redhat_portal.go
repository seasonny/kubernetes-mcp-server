package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const (
	rhSSOURL      = "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
	rhAPIURL      = "https://api.access.redhat.com/support/v1"
	rhClientID    = "rhsm-api"
	tokenVar      = "RH_PORTAL_TOKEN"
	mustGatherDir = "must-gather.local."
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

// Case represents a Red Hat support case.
type Case struct {
	Product      string `json:"product"`
	Version      string `json:"version"`
	CaseType     string `json:"caseType"`
	Description  string `json:"description"`
	Environment  string `json:"environment"`
	CaseLanguage string `json:"caseLanguage"`
	Severity     int    `json:"severity"`
	Summary      string `json:"summary"`
}

// CaseCreationResponse represents the response after creating a case.
type CaseCreationResponse struct {
	Location []string `json:"location"`
}

// Attachment represents a file attached to a case.
type Attachment struct {
	CaseNumber         string  `json:"caseNumber"`
	UUID               string  `json:"uuid"`
	Checksum           string  `json:"checksum"`
	CreatedDate        string  `json:"createdDate"`
	CreatedBy          string  `json:"createdBy"`
	FileName           string  `json:"fileName"`
	FileType           string  `json:"fileType"`
	ID                 string  `json:"id"`
	IsArchived         bool    `json:"isArchived"`
	IsDeprecated       bool    `json:"isDeprecated"`
	IsPrivate          bool    `json:"isPrivate"`
	LastModifiedDate   string  `json:"lastModifiedDate"`
	Link               string  `json:"link"`
	ModifiedBy         string  `json:"modifiedBy"`
	Size               int64   `json:"size"`
	SizeKB             float64 `json:"sizeKB"`
	DownloadRestricted bool    `json:"downloadRestricted"`
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

// createCase creates a new support case on the Red Hat Customer Portal.
func (s *Server) createCase(apiURL, accessToken string, caseData Case) (string, error) {
	jsonData, err := json.Marshal(caseData)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", apiURL+"/cases", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := s.httpClient
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create case, status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var caseCreationResponse CaseCreationResponse
	if err := json.NewDecoder(resp.Body).Decode(&caseCreationResponse); err != nil {
		return "", err
	}

	if len(caseCreationResponse.Location) == 0 {
		return "", fmt.Errorf("case creation response did not include a location")
	}

	// Extract case number from the location URL
	parts := strings.Split(caseCreationResponse.Location[0], "/")
	caseNumber := parts[len(parts)-1]

	return caseNumber, nil
}

// uploadAttachment uploads a file to a support case.
func (s *Server) uploadAttachment(apiURL, accessToken, caseNumber, filePath string) (*Attachment, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)

	go func() {
		defer pw.Close()
		defer writer.Close()
		part, err := writer.CreateFormFile("file", filepath.Base(filePath))
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(part, file); err != nil {
			pw.CloseWithError(err)
			return
		}
	}()

	req, err := http.NewRequest("POST", apiURL+"/cases/"+caseNumber+"/attachments", pr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := s.httpClient
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to upload attachment, status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var attachments []Attachment
	if err := json.NewDecoder(resp.Body).Decode(&attachments); err != nil {
		// Try to read the body for better error logging
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("failed to decode attachment response and failed to read body: %w", err)
		}
		return nil, fmt.Errorf("failed to upload attachment: %w. Body: %s", err, string(bodyBytes))
	}

	if len(attachments) == 0 {
		return nil, fmt.Errorf("attachment response did not include attachment information")
	}

	return &attachments[0], nil
}

func (s *Server) getOpenShiftVersion() (string, error) {
	cmd := exec.Command("oc", "version", "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to execute 'oc version': %w", err)
	}

	var versionInfo struct {
		ServerVersion struct {
			Major      string `json:"major"`
			Minor      string `json:"minor"`
			GitVersion string `json:"gitVersion"`
		} `json:"serverVersion"`
		OpenshiftVersion string `json:"openshiftVersion"` // Add this field
	}

	if err := json.Unmarshal(output, &versionInfo); err != nil {
		return "", fmt.Errorf("failed to parse 'oc version' output: %w", err)
	}

	// Prefer openshiftVersion field
	if versionInfo.OpenshiftVersion != "" {
		// Extract X.Y from "X.Y.Z"
		parts := strings.Split(versionInfo.OpenshiftVersion, ".")
		if len(parts) >= 2 {
			return fmt.Sprintf("%s.%s", parts[0], parts[1]), nil
		}
	}

	// Fallback to ServerVersion.Major and ServerVersion.Minor
	if versionInfo.ServerVersion.Major != "" && versionInfo.ServerVersion.Minor != "" {
		return fmt.Sprintf("%s.%s", versionInfo.ServerVersion.Major, versionInfo.ServerVersion.Minor), nil
	}

	// Fallback to parsing ServerVersion.GitVersion
	if versionInfo.ServerVersion.GitVersion != "" {
		// Extract X.Y from "vX.Y.Z" or "X.Y.Z"
		versionStr := strings.TrimPrefix(versionInfo.ServerVersion.GitVersion, "v")
		parts := strings.Split(versionStr, ".")
		if len(parts) >= 2 {
			return fmt.Sprintf("%s.%s", parts[0], parts[1]), nil
		}
	}

	return "", errors.New("could not determine OpenShift version from 'oc version' output")
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

func (s *Server) initRedHatPortal() []server.ServerTool {
	return []server.ServerTool{
		{
			Tool: mcp.NewTool(
				"create_case_rh_portal",
				mcp.WithDescription("Creates a new support case on the Red Hat Customer Portal for OpenShift."),
				mcp.WithString("summary", mcp.Description("A brief summary of the issue."), mcp.Required()),
				mcp.WithString("description", mcp.Description("A detailed description of the issue."), mcp.Required()),
				mcp.WithString("version", mcp.Description("The OpenShift version (e.g., 4.12). If not provided, it will be auto-detected.")),
				mcp.WithString("environment", mcp.Description("The environment where the issue is occurring (e.g., Production, Staging).")),
			),
			Handler: s.createCaseOnRedHatPortal,
		},
		{
			Tool: mcp.NewTool(
				"upload_attachment_rh_portal",
				mcp.WithDescription("Uploads an attachment to a Red Hat Portal case."),
				mcp.WithString("case-number", mcp.Description("The Red Hat Portal case number."), mcp.Required()),
				mcp.WithString("file_path", mcp.Description("The path to the file to upload."), mcp.Required()),
			),
			Handler: s.uploadAttachmentToRedHatPortal,
		},
	}
}

func (s *Server) createCaseOnRedHatPortal(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	summary, ok := request.GetArguments()["summary"].(string)
	if !ok || summary == "" {
		return nil, errors.New("summary is a required field")
	}
	description, ok := request.GetArguments()["description"].(string)
	if !ok || description == "" {
		return nil, errors.New("description is a required field")
	}

	// Get version
	version, _ := request.GetArguments()["version"].(string)
	if version == "" {
		autoVersion, err := s.getOpenShiftVersionFunc()
		if err != nil {
			return NewTextResult("", fmt.Errorf("failed to auto-detect OpenShift version, please provide it manually. Error: %w", err)), nil
		}
		version = autoVersion
	}

	environment, _ := request.GetArguments()["environment"].(string)

	referenceToken, err := getRefreshToken()
	if err != nil {
		return NewTextResult("", err), nil
	}

	accessToken, err := s.getAccessToken(rhSSOURL, referenceToken)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to get access token: %w", err)), nil
	}

	caseData := Case{
		Summary:      summary,
		Description:  description,
		Product:      "OpenShift Container Platform",
		Version:      version,
		Severity:     3,
		CaseType:     "RCA Only",
		Environment:  environment,
		CaseLanguage: "zh_TW",
	}

	caseNumber, err := s.createCase(rhAPIURL, accessToken, caseData)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to create case: %w", err)), nil
	}

	return NewTextResult(fmt.Sprintf("Case %s created successfully.", caseNumber), nil), nil
}

func (s *Server) uploadAttachmentToRedHatPortal(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	caseNumber, ok := request.GetArguments()["case-number"].(string)
	if !ok || caseNumber == "" {
		return nil, errors.New("case-number is a required field")
	}
	filePath, ok := request.GetArguments()["file_path"].(string)
	if !ok || filePath == "" {
		return nil, errors.New("file_path is a required field")
	}

	referenceToken, err := getRefreshToken()
	if err != nil {
		return NewTextResult("", err), nil
	}

	accessToken, err := s.getAccessToken(rhSSOURL, referenceToken)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to get access token: %w", err)), nil
	}

	attachment, err := s.uploadAttachment(rhAPIURL, accessToken, caseNumber, filePath)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to upload attachment: %w", err)), nil
	}

	return NewTextResult(fmt.Sprintf("Attachment uploaded successfully:\n  UUID: %s\n  File Name: %s\n  Size: %d bytes\n  Link: %s\n", attachment.UUID, attachment.FileName, attachment.Size, attachment.Link), nil), nil
}
