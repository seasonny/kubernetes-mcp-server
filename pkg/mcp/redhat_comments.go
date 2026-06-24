package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/mark3labs/mcp-go/mcp"
)

// CaseComment represents a Hydra CaseComment (docs/mcp_case_api_integration.md §4.1).
type CaseComment struct {
	ID                string `json:"id,omitempty"`
	CaseNumber        string `json:"caseNumber,omitempty"`
	CommentBody       string `json:"commentBody,omitempty"`
	CreatedDate       string `json:"createdDate,omitempty"`
	PublishedDate     string `json:"publishedDate,omitempty"`
	CreatedBy         string `json:"createdBy,omitempty"`
	CreatedByType     string `json:"createdByType,omitempty"`
	ContentType       string `json:"contentType,omitempty"`
	IsDraft           bool   `json:"isDraft,omitempty"`
	DoNotChangeStatus bool   `json:"doNotChangeStatus,omitempty"`
}

type caseCommentsResponse struct {
	Comments []CaseComment `json:"comments"`
	Source   string        `json:"source"`
}

type caseCommentQuery struct {
	StartDate string
	EndDate   string
	SortField string
	SortOrder string
}

func parseCaseCommentQuery(args map[string]any) caseCommentQuery {
	q := caseCommentQuery{}
	if v, ok := args["start-date"].(string); ok {
		q.StartDate = v
	}
	if v, ok := args["end-date"].(string); ok {
		q.EndDate = v
	}
	if v, ok := args["sort-field"].(string); ok {
		q.SortField = v
	}
	if v, ok := args["sort-order"].(string); ok {
		q.SortOrder = v
	}
	return q
}

// getCaseComments retrieves all comments for a specific support case.
func (s *Server) getCaseComments(apiURL, accessToken, caseNumber string, query caseCommentQuery) ([]CaseComment, error) {
	reqURL := apiURL + "/cases/" + url.PathEscape(caseNumber) + "/comments"
	parsed, err := url.Parse(reqURL)
	if err != nil {
		return nil, err
	}
	params := parsed.Query()
	if query.StartDate != "" {
		params.Set("startDate", query.StartDate)
	}
	if query.EndDate != "" {
		params.Set("endDate", query.EndDate)
	}
	if query.SortField != "" {
		params.Set("sortField", query.SortField)
	}
	if query.SortOrder != "" {
		params.Set("sortOrder", query.SortOrder)
	}
	parsed.RawQuery = params.Encode()

	req, err := http.NewRequest("GET", parsed.String(), nil)
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
		return nil, fmt.Errorf("failed to get case comments, status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var comments []CaseComment
	if err := json.Unmarshal(bodyBytes, &comments); err != nil {
		return nil, err
	}

	return comments, nil
}

// addCaseComment adds a new comment to a specific support case.
func (s *Server) addCaseComment(apiURL, accessToken, caseNumber, text string, doNotChangeStatus bool) (*CaseComment, error) {
	commentData := CaseComment{
		CommentBody:       text,
		DoNotChangeStatus: doNotChangeStatus,
	}
	jsonData, err := json.Marshal(commentData)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", apiURL+"/cases/"+url.PathEscape(caseNumber)+"/comments", bytes.NewBuffer(jsonData))
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

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to add case comment, status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	var newComment CaseComment
	if err := json.Unmarshal(bodyBytes, &newComment); err != nil {
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

	query := parseCaseCommentQuery(request.GetArguments())
	comments, err := s.getCaseComments(rhAPIURL, accessToken, caseNumber, query)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to get case comments: %w", err)), nil
	}

	return NewJSONResult(caseCommentsResponse{
		Comments: comments,
		Source:   "hydra:getCaseComments",
	}, nil), nil
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

	doNotChangeStatus := true
	if v, ok := request.GetArguments()["do-not-change-status"].(bool); ok {
		doNotChangeStatus = v
	}

	referenceToken, err := getRefreshToken()
	if err != nil {
		return NewTextResult("", err), nil
	}

	accessToken, err := s.getAccessToken(rhSSOURL, referenceToken)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to get access token: %w", err)), nil
	}

	comment, err := s.addCaseComment(rhAPIURL, accessToken, caseNumber, text, doNotChangeStatus)
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to add comment: %w", err)), nil
	}

	return NewJSONResult(comment, nil), nil
}
