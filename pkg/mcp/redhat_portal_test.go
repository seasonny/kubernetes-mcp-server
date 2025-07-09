package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		c.mcpServer.httpClient = mockAPI.Client()
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
		c.mcpServer.httpClient = mockAPI.Client()

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
