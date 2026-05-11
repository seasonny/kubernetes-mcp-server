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

// Comment represents a comment on a Red Hat support case.
type Comment struct {
	Text        string `json:"commentBody"`
	Public      *bool  `json:"public,omitempty"`
	CreatedBy   string `json:"createdBy,omitempty"`
	CreatedDate string `json:"createdDate,omitempty"`
}

// getCaseComments retrieves all comments for a specific support case.
func (s *Server) getCaseComments(apiURL, accessToken, caseNumber string) ([]Comment, error) {
	req, err := http.NewRequest("GET", apiURL+"/cases/"+caseNumber+"/comments", nil)
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
		return nil, fmt.Errorf("failed to get case comments, status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var comments []Comment
	if err := json.NewDecoder(resp.Body).Decode(&comments); err != nil {
		return nil, err
	}

	return comments, nil
}

// addCaseComment adds a new comment to a specific support case.
func (s *Server) addCaseComment(apiURL, accessToken, caseNumber, text string, public bool) (*Comment, error) {
	commentData := struct {
		CommentBody string `json:"commentBody"`
	}{
		CommentBody: text,
	}
	jsonData, err := json.Marshal(commentData)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", apiURL+"/cases/"+caseNumber+"/comments", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := s.httpClient
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to add case comment, status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var newComment Comment
	if err := json.NewDecoder(resp.Body).Decode(&newComment); err != nil {
		return nil, err
	}

	return &newComment, nil
}

func (s *Server) readCaseCommentsFromRedHatPortal(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	comments, err := s.getCaseComments(rhAPIURL, accessToken, caseNumber)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to get case comments: %w", err)), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Comments for Case %s:\n\n", caseNumber))
	if len(comments) == 0 {
		sb.WriteString("No comments found.")
	} else {
		for i, c := range comments {
			visibility := "Private"
			if c.Public != nil && *c.Public {
				visibility = "Public"
			}
			sb.WriteString(fmt.Sprintf("[%d] %s (%s, %s):\n%s\n\n", i+1, c.CreatedBy, c.CreatedDate, visibility, c.Text))
		}
	}

	return NewTextResult(sb.String(), nil), nil
}

func (s *Server) addCaseCommentToRedHatPortal(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	caseNumber, ok := request.GetArguments()["case-number"].(string)
	if !ok || caseNumber == "" {
		return nil, errors.New("case-number is a required field")
	}
	text, ok := request.GetArguments()["text"].(string)
	if !ok || text == "" {
		return nil, errors.New("text is a required field")
	}

	// Default to public as per user request
	public := true
	if p, ok := request.GetArguments()["public"].(bool); ok {
		public = p
	}

	referenceToken, err := getRefreshToken()
	if err != nil {
		return NewTextResult("", err), nil
	}

	accessToken, err := s.getAccessToken(rhSSOURL, referenceToken)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to get access token: %w", err)), nil
	}

	comment, err := s.addCaseComment(rhAPIURL, accessToken, caseNumber, text, public)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to add comment: %w", err)), nil
	}

	return NewTextResult(fmt.Sprintf("Comment added successfully to Case %s.\nVisibility: %v\nText: %s", caseNumber, comment.Public, comment.Text), nil), nil
}
