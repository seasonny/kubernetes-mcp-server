package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/mark3labs/mcp-go/mcp"
)

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

type caseAttachmentsResponse struct {
	Attachments []Attachment `json:"attachments"`
}

// listAttachments lists attachments for a support case.
func (s *Server) listAttachments(apiURL, accessToken, caseNumber string) ([]Attachment, error) {
	reqURL := apiURL + "/cases/" + url.PathEscape(caseNumber) + "/attachments"
	req, err := http.NewRequest("GET", reqURL, nil)
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

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list attachments, status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var attachments []Attachment
	if err := json.Unmarshal(bodyBytes, &attachments); err != nil {
		return nil, err
	}

	return attachments, nil
}

func (s *Server) listCaseAttachmentsFromRedHatPortal(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	attachments, err := s.listAttachments(rhAPIURL, accessToken, caseNumber)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to list attachments: %w", err)), nil
	}

	return NewJSONResult(caseAttachmentsResponse{Attachments: attachments}, nil), nil
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
