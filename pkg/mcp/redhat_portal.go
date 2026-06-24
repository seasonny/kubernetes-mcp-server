package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
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
		OpenshiftVersion string `json:"openshiftVersion"`
	}

	if err := json.Unmarshal(output, &versionInfo); err != nil {
		return "", fmt.Errorf("failed to parse 'oc version' output: %w", err)
	}

	if versionInfo.OpenshiftVersion != "" {
		parts := strings.Split(versionInfo.OpenshiftVersion, ".")
		if len(parts) >= 2 {
			return fmt.Sprintf("%s.%s", parts[0], parts[1]), nil
		}
	}

	if versionInfo.ServerVersion.Major != "" && versionInfo.ServerVersion.Minor != "" {
		return fmt.Sprintf("%s.%s", versionInfo.ServerVersion.Major, versionInfo.ServerVersion.Minor), nil
	}

	if versionInfo.ServerVersion.GitVersion != "" {
		versionStr := strings.TrimPrefix(versionInfo.ServerVersion.GitVersion, "v")
		parts := strings.Split(versionStr, ".")
		if len(parts) >= 2 {
			return fmt.Sprintf("%s.%s", parts[0], parts[1]), nil
		}
	}

	return "", errors.New("could not determine OpenShift version from 'oc version' output")
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
				"read_case_rh_portal",
				mcp.WithDescription("Retrieves details of a specific support case from the Red Hat Customer Portal."),
				mcp.WithString("case-number", mcp.Description("The Red Hat Portal case number."), mcp.Required()),
			),
			Handler: s.readCaseFromRedHatPortal,
		},
		{
			Tool: mcp.NewTool(
				"read_case_comments_rh_portal",
				mcp.WithDescription("Retrieves all comments for a specific support case from the Red Hat Customer Portal."),
				mcp.WithString("case-number", mcp.Description("The Red Hat Portal case number."), mcp.Required()),
				mcp.WithString("start-date", mcp.Description("ISO 8601 start date for incremental polling (maps to startDate).")),
				mcp.WithString("end-date", mcp.Description("ISO 8601 end date (maps to endDate).")),
				mcp.WithString("sort-field", mcp.Description("Sort field, e.g. createdDate (maps to sortField).")),
				mcp.WithString("sort-order", mcp.Description("Sort order: asc or desc (maps to sortOrder).")),
			),
			Handler: s.readCaseCommentsFromRedHatPortal,
		},
		{
			Tool: mcp.NewTool(
				"add_case_comment_rh_portal",
				mcp.WithDescription("Adds a new comment to a specific support case on the Red Hat Customer Portal."),
				mcp.WithString("case-number", mcp.Description("The Red Hat Portal case number."), mcp.Required()),
				mcp.WithString("text", mcp.Description("The text of the comment."), mcp.Required()),
				mcp.WithBoolean("public", mcp.Description("Whether the comment should be public (visible to support). Defaults to true.")),
				mcp.WithBoolean("do-not-change-status", mcp.Description("When true, do not change case status on comment (maps to doNotChangeStatus). Defaults to true.")),
			),
			Handler: s.addCaseCommentToRedHatPortal,
		},
		{
			Tool: mcp.NewTool(
				"list_case_attachments_rh_portal",
				mcp.WithDescription("Lists attachments for a specific support case from the Red Hat Customer Portal."),
				mcp.WithString("case-number", mcp.Description("The Red Hat Portal case number."), mcp.Required()),
			),
			Handler: s.listCaseAttachmentsFromRedHatPortal,
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
