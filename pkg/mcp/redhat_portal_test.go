package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// redHatMockClient routes Red Hat API requests to a local httptest server.
func redHatMockClient(serverURL string) *http.Client {
	target, _ := url.Parse(serverURL)
	return &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			return http.DefaultTransport.RoundTrip(req)
		}),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestCreateCaseOnRedHatPortalWithVersion(t *testing.T) {
	testCase(t, func(c *mcpContext) {
		// This server will act as the mock Red Hat API
		mockAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/auth/realms/redhat-external/protocol/openid-connect/token":
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(TokenResponse{AccessToken: "test-access-token"})
			case "/support/v1/cases":
				var caseData Case
				err := json.NewDecoder(r.Body).Decode(&caseData)
				require.NoError(t, err)
				assert.Equal(t, "Manual Version", caseData.Version) // Assert manual version is used
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(CaseCreationResponse{
					Location: []string{"https://api.access.redhat.com/support/v1/cases/12345"},
				})
			default:
				http.NotFound(w, r)
			}
		}))
		defer mockAPI.Close()

		// Point the server's http client to the test server
		c.mcpServer.httpClient = redHatMockClient(mockAPI.URL)
		// Override the getOpenShiftVersion function to simulate failure
		c.mcpServer.getOpenShiftVersionFunc = func() (string, error) {
			return "", fmt.Errorf("oc command not found")
		}

		// Set the token env var
		t.Setenv(tokenVar, "test-refresh-token")

		// Call the tool with manual version
		toolResult, err := c.callTool("create_case_rh_portal", map[string]interface{}{
			"summary":     "Test Summary",
			"description": "Test Description",
			"version":     "Manual Version",
		})

		// Assertions
		require.NoError(t, err)
		require.False(t, toolResult.IsError)
		assert.Contains(t, toolResult.Content[0].(mcp.TextContent).Text, "Case 12345 created successfully.")
	})
}

func TestUploadAttachmentToRedHatPortal(t *testing.T) {
	testCase(t, func(c *mcpContext) {
		// Create a temporary file for upload
		tmpfile, err := os.CreateTemp("", "test-upload-*.txt")
		require.NoError(t, err)
		defer os.Remove(tmpfile.Name())
		testData := "this is a test file"
		_, err = tmpfile.Write([]byte(testData))
		require.NoError(t, err)
		err = tmpfile.Close()
		require.NoError(t, err)

		// This server will act as the mock Red Hat API
		mockAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/auth/realms/redhat-external/protocol/openid-connect/token":
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(TokenResponse{AccessToken: "test-access-token"})
			case "/support/v1/cases/54321/attachments":
				// Verify the uploaded file content
				err := r.ParseMultipartForm(10 << 20) // 10 MB
				require.NoError(t, err, "Failed to parse multipart form")
				file, handler, err := r.FormFile("file")
				require.NoError(t, err, "Failed to get form file")
				defer file.Close()
				assert.Equal(t, filepath.Base(tmpfile.Name()), handler.Filename)
				fileBytes, err := io.ReadAll(file)
				require.NoError(t, err)
				assert.Equal(t, testData, string(fileBytes))

				// Send the response
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode([]Attachment{{
					UUID:     "test-uuid-123",
					FileName: handler.Filename,
					Size:     int64(len(testData)),
					Link:     "https://example.com/new-attachment",
				}})
			default:
				http.NotFound(w, r)
			}
		}))
		defer mockAPI.Close()

		// Point the server's http client to the test server
		c.mcpServer.httpClient = redHatMockClient(mockAPI.URL)

		// Set the token env var
		t.Setenv(tokenVar, "test-refresh-token")

		// Call the tool
		toolResult, err := c.callTool("upload_attachment_rh_portal", map[string]interface{}{
			"case-number": "54321",
			"file_path":   tmpfile.Name(),
		})

		// Assertions
		require.NoError(t, err, "callTool should not return an error")
		require.False(t, toolResult.IsError, "toolResult should not be an error")
		expected := fmt.Sprintf("Attachment uploaded successfully:\n  UUID: %s\n  File Name: %s\n  Size: %d bytes\n  Link: %s\n", "test-uuid-123", filepath.Base(tmpfile.Name()), len(testData), "https://example.com/new-attachment")
		assert.Equal(t, expected, toolResult.Content[0].(mcp.TextContent).Text)
	})
}

func TestReadCaseCommentsReturnsJSONContract(t *testing.T) {
	testCase(t, func(c *mcpContext) {
		mockAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/auth/realms/redhat-external/protocol/openid-connect/token":
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(TokenResponse{AccessToken: "test-access-token"})
			case "/support/v1/cases/04444508/comments":
				assert.Equal(t, "createdDate", r.URL.Query().Get("sortField"))
				assert.Equal(t, "asc", r.URL.Query().Get("sortOrder"))
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode([]CaseComment{{
					ID:            "127",
					CaseNumber:    "04444508",
					CommentBody:   "please run oc get node",
					CreatedDate:   "2026-06-24T10:05:00Z",
					PublishedDate: "2026-06-24T10:05:00Z",
					CreatedBy:     "Jane Doe",
					CreatedByType: "ASSOCIATE",
					ContentType:   "TEXT",
				}})
			default:
				http.NotFound(w, r)
			}
		}))
		defer mockAPI.Close()

		c.mcpServer.httpClient = redHatMockClient(mockAPI.URL)
		t.Setenv(tokenVar, "test-refresh-token")

		toolResult, err := c.callTool("read_case_comments_rh_portal", map[string]interface{}{
			"case-number": "04444508",
			"sort-field":  "createdDate",
			"sort-order":  "asc",
		})

		require.NoError(t, err)
		require.False(t, toolResult.IsError)

		var payload caseCommentsResponse
		err = json.Unmarshal([]byte(toolResult.Content[0].(mcp.TextContent).Text), &payload)
		require.NoError(t, err)
		assert.Equal(t, "hydra:getCaseComments", payload.Source)
		require.Len(t, payload.Comments, 1)
		assert.Equal(t, "ASSOCIATE", payload.Comments[0].CreatedByType)
		assert.Equal(t, "127", payload.Comments[0].ID)
	})
}

func TestReadCaseReturnsJSONContract(t *testing.T) {
	testCase(t, func(c *mcpContext) {
		mockAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/auth/realms/redhat-external/protocol/openid-connect/token":
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(TokenResponse{AccessToken: "test-access-token"})
			case "/support/v1/cases/04444508":
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(Case{
					CaseNumber:              "04444508",
					Status:                  "Waiting on Customer",
					Severity:                "3",
					Summary:                 "節點 NotReady",
					Product:                 "Red Hat OpenShift Container Platform",
					Version:                 "4.16",
					OpenshiftClusterID:      "cluster-abc",
					OpenshiftClusterVersion: "4.16.12",
					LastModifiedDate:        "2026-06-24T09:00:00Z",
				})
			default:
				http.NotFound(w, r)
			}
		}))
		defer mockAPI.Close()

		c.mcpServer.httpClient = redHatMockClient(mockAPI.URL)
		t.Setenv(tokenVar, "test-refresh-token")

		toolResult, err := c.callTool("read_case_rh_portal", map[string]interface{}{
			"case-number": "04444508",
		})

		require.NoError(t, err)
		require.False(t, toolResult.IsError)

		var caseData Case
		err = json.Unmarshal([]byte(toolResult.Content[0].(mcp.TextContent).Text), &caseData)
		require.NoError(t, err)
		assert.Equal(t, "04444508", caseData.CaseNumber)
		assert.Equal(t, "Waiting on Customer", caseData.Status)
		assert.Equal(t, "cluster-abc", caseData.OpenshiftClusterID)
	})
}

func TestAddCaseCommentReturnsCaseCommentJSON(t *testing.T) {
	testCase(t, func(c *mcpContext) {
		mockAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/auth/realms/redhat-external/protocol/openid-connect/token":
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(TokenResponse{AccessToken: "test-access-token"})
			case "/support/v1/cases/04444508/comments":
				var body CaseComment
				require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
				assert.Equal(t, "test reply", body.CommentBody)
				assert.True(t, body.DoNotChangeStatus)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(CaseComment{
					ID:            "999",
					CaseNumber:    "04444508",
					CommentBody:   body.CommentBody,
					CreatedDate:   "2026-06-24T11:00:00Z",
					CreatedBy:     "Agent",
					CreatedByType: "ASSOCIATE",
				})
			default:
				http.NotFound(w, r)
			}
		}))
		defer mockAPI.Close()

		c.mcpServer.httpClient = redHatMockClient(mockAPI.URL)
		t.Setenv(tokenVar, "test-refresh-token")

		toolResult, err := c.callTool("add_case_comment_rh_portal", map[string]interface{}{
			"case-number": "04444508",
			"text":        "test reply",
		})

		require.NoError(t, err)
		require.False(t, toolResult.IsError)

		var comment CaseComment
		err = json.Unmarshal([]byte(toolResult.Content[0].(mcp.TextContent).Text), &comment)
		require.NoError(t, err)
		assert.Equal(t, "999", comment.ID)
		assert.Equal(t, "04444508", comment.CaseNumber)
	})
}
