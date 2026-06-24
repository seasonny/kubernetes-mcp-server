package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

// Case represents a Red Hat support case (Hydra getCase).
type Case struct {
	CaseNumber              string `json:"caseNumber,omitempty"`
	Product                 string `json:"product,omitempty"`
	Version                 string `json:"version,omitempty"`
	CaseType                string `json:"caseType,omitempty"`
	Description             string `json:"description,omitempty"`
	Environment             string `json:"environment,omitempty"`
	CaseLanguage            string `json:"caseLanguage,omitempty"`
	Severity                any    `json:"severity,omitempty"`
	Summary                 string `json:"summary,omitempty"`
	Status                  string `json:"status,omitempty"`
	CreatedBy               string `json:"createdBy,omitempty"`
	CreatedDate             string `json:"createdDate,omitempty"`
	LastModifiedDate        string `json:"lastModifiedDate,omitempty"`
	OpenshiftClusterID      string `json:"openshiftClusterID,omitempty"`
	OpenshiftClusterVersion string `json:"openshiftClusterVersion,omitempty"`
	ResolutionDescription   any    `json:"resolutionDescription,omitempty"`
}

// CaseCreationResponse represents the response after creating a case.
type CaseCreationResponse struct {
	Location []string `json:"location"`
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

// getCase retrieves details of a specific support case.
func (s *Server) getCase(apiURL, accessToken, caseNumber string) (*Case, error) {
	req, err := http.NewRequest("GET", apiURL+"/cases/"+caseNumber, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := s.httpClient
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get case, status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var caseData Case
	if err := json.NewDecoder(resp.Body).Decode(&caseData); err != nil {
		return nil, err
	}

	return &caseData, nil
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

func (s *Server) readCaseFromRedHatPortal(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	caseNumber, ok := request.GetArguments()["case-number"].(string)
	if !ok || caseNumber == "" {
		return nil, errors.New("case-number is a required field")
	}

	referenceToken, err := getRefreshToken()
	if err != nil {
		return NewTextResult("", err), nil
	}

	accessToken, err := s.getAccessToken(rhSSOURL, referenceToken)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to get access token: %w", err)), nil
	}

	caseData, err := s.getCase(rhAPIURL, accessToken, caseNumber)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to get case: %w", err)), nil
	}

	return NewJSONResult(caseData, nil), nil
}
