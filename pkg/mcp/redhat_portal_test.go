package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockExecCommand is a helper to mock exec.Command for testing.
func mockExecCommand(t *testing.T, command string, args []string, output string, err error) func() {
	originalExecCommand := execCommand
	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == command {
			// Create a real command that will print the mocked output
			// This avoids complex mocking of StdoutPipe etc.
			cs := []string{"-test.run=TestHelperProcess", "--", name}
			cs = append(cs, arg...)
			cmd := exec.Command(os.Args[0], cs...)
			cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1",
				"STDOUT=" + output,
			}
			if err != nil {
				cmd.Env = append(cmd.Env, "EXIT_CODE=1")
			}
			return cmd
		}
		return originalExecCommand(name, arg...)
	}
	return func() {
		execCommand = originalExecCommand
	}
}

// TestHelperProcess isn't a real test. It's used as a helper for TestExecCommand.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	fmt.Fprint(os.Stdout, os.Getenv("STDOUT"))
	i, _ := stdstrconv.Atoi(os.Getenv("EXIT_CODE"))
	os.Exit(i)
}

func TestCreateCaseOnRedHatPortal(t *testing.T) {
	// Mock successful oc version command
	const ocVersionOutput = `{
		"serverVersion": {
			"gitVersion": "v4.12.1"
		}
	}`
	cleanup := mockExecCommand(t, "oc", []string{"version", "-o", "json"}, ocVersionOutput, nil)
	defer cleanup()

	testCase(t, func(c *mcpContext) {
		// This server will act as the mock Red Hat API
		mockAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/auth/realms/redhat-external/protocol/openid-connect/token":
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(TokenResponse{AccessToken: "test-access-token"})
			case "/support/v1/cases":
				// Verify the request body
				var caseData Case
				err := json.NewDecoder(r.Body).Decode(&caseData)
				require.NoError(t, err, "Failed to decode request body")
				assert.Equal(t, "Test Summary", caseData.Summary)
				assert.Equal(t, "Test Description", caseData.Description)
				assert.Equal(t, "OpenShift Container Platform", caseData.Product)
				assert.Equal(t, "4.12", caseData.Version) // From mocked oc version
				assert.Equal(t, 3, caseData.Severity)
				assert.Equal(t, "RCA Only", caseData.CaseType)
				assert.Equal(t, "zh_TW", caseData.CaseLanguage)

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

		// Override the hardcoded URLs to point to our mock server
		originalRhSSOURL := rhSSOURL
		originalRhAPIURL := rhAPIURL
		rhSSOURL = mockAPI.URL + "/auth/realms/redhat-external/protocol/openid-connect/token"
		rhAPIURL = mockAPI.URL + "/support/v1"
		defer func() {
			rhSSOURL = originalRhSSOURL
			rhAPIURL = originalRhAPIURL
		}()

		// Set the token env var
		t.Setenv(tokenVar, "test-refresh-token")

		// Call the tool
		toolResult, err := c.callTool("create_case_rh_portal", map[string]interface{}{
			"summary":     "Test Summary",
			"description": "Test Description",
		})

		// Assertions
		require.NoError(t, err, "callTool should not return an error")
		require.False(t, toolResult.IsError, "toolResult should not be an error")
		expected := "Case 12345 created successfully."
		assert.Equal(t, expected, toolResult.Content[0].(mcp.TextContent).Text)
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

		// Override the hardcoded URLs to point to our mock server
		originalRhSSOURL := rhSSOURL
		originalRhAPIURL := rhAPIURL
		rhSSOURL = mockAPI.URL + "/auth/realms/redhat-external/protocol/openid-connect/token"
		rhAPIURL = mockAPI.URL + "/support/v1"
		defer func() {
			rhSSOURL = originalRhSSOURL
			rhAPIURL = originalRhAPIURL
		}()

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
