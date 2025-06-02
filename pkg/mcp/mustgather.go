package mcp

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func (s *Server) initMustGather() []server.ServerTool {
	return []server.ServerTool{
		{Tool: mcp.NewTool("oc_adm_must_gather",
			mcp.WithDescription("Collects the information from your cluster that is most likely needed for debugging issues using `oc adm must-gather`."),
			mcp.WithString("outputDirectory", mcp.Description("The directory where the collected data will be stored. If not provided, a temporary directory will be used.")),
			mcp.WithArray("flags", mcp.Description("Additional flags to pass to the `oc adm must-gather` command (e.g., `['--timeout=5m', '--image=quay.io/openshift/origin-must-gather:latest']`)."),
				func(schema map[string]interface{}) {
					schema["type"] = "array"
					schema["items"] = map[string]interface{}{
						"type": "string",
					}
				},
			),
			// Tool annotations
			mcp.WithTitleAnnotation("OpenShift: Must-Gather"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithOpenWorldHintAnnotation(true),
		), Handler: s.ocAdmMustGather},
	}
}

func (s *Server) ocAdmMustGather(ctx context.Context, ctr mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	outputDirectory := ctr.GetArguments()["outputDirectory"]
	flagsArg := ctr.GetArguments()["flags"]

	cmdArgs := []string{"adm", "must-gather"}

	if outputDirectory != nil {
		if dir, ok := outputDirectory.(string); ok && dir != "" {
			cmdArgs = append(cmdArgs, "--dest-dir", dir)
		}
	}

	if flagsArg != nil {
		if flags, ok := flagsArg.([]interface{}); ok {
			for _, flag := range flags {
				if f, ok := flag.(string); ok {
					cmdArgs = append(cmdArgs, f)
				}
			}
		}
	}

	cmd := exec.CommandContext(ctx, "oc", cmdArgs...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return NewTextResult("", fmt.Errorf("failed to execute 'oc adm must-gather': %v\nOutput: %s", err, output)), nil
	}

	return NewTextResult(fmt.Sprintf("oc adm must-gather executed successfully.\nOutput:\n%s", strings.TrimSpace(string(output))), nil), nil
}
