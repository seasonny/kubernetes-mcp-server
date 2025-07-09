package mcp

import (
	"context"
	"net/http"

	"github.com/manusa/kubernetes-mcp-server/pkg/kubernetes"
	"github.com/manusa/kubernetes-mcp-server/pkg/version"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type Configuration struct {
	Profile Profile
	// When true, expose only tools annotated with readOnlyHint=true
	ReadOnly bool
	// When true, disable tools annotated with destructiveHint=true
	DisableDestructive bool
	Kubeconfig         string
}

type Server struct {
	configuration           *Configuration
	server                  *server.MCPServer
	k                       *kubernetes.Kubernetes
	httpClient              *http.Client
	getOpenShiftVersionFunc func() (string, error)
}

func NewSever(configuration Configuration) (*Server, error) {
	s := &Server{
		configuration: &configuration,
		server: server.NewMCPServer(
			version.BinaryName,
			version.Version,
			server.WithResourceCapabilities(true, true),
			server.WithPromptCapabilities(true),
			server.WithToolCapabilities(true),
			server.WithLogging(),
		),
		httpClient: &http.Client{},
	}
	s.getOpenShiftVersionFunc = s.getOpenShiftVersion
	if err := s.reloadKubernetesClient(); err != nil {
		return nil, err
	}
	s.k.WatchKubeConfig(s.reloadKubernetesClient)
	return s, nil
}

func isFalse(value *bool) bool {
	return value == nil || !*value
}

func (s *Server) reloadKubernetesClient() error {
	k, err := kubernetes.NewKubernetes(s.configuration.Kubeconfig)
	if err != nil {
		return err
	}
	s.k = k
	applicableTools := make([]server.ServerTool, 0)
	for _, tool := range s.configuration.Profile.GetTools(s) {
		if s.configuration.ReadOnly && isFalse(tool.Tool.Annotations.ReadOnlyHint) {
			continue
		}
		if s.configuration.DisableDestructive && isFalse(tool.Tool.Annotations.ReadOnlyHint) && !isFalse(tool.Tool.Annotations.DestructiveHint) {
			continue
		}
		applicableTools = append(applicableTools, tool)
	}
	s.server.SetTools(applicableTools...)
	return nil
}

func (s *Server) ServeStdio() error {
	return server.ServeStdio(s.server)
}

func (s *Server) ServeSse(baseUrl string) *server.SSEServer {
	options := make([]server.SSEOption, 0)
	options = append(options, server.WithSSEContextFunc(contextFunc))
	if baseUrl != "" {
		options = append(options, server.WithBaseURL(baseUrl))
	}
	return server.NewSSEServer(s.server, options...)
}

func (s *Server) Close() {
	if s.k != nil {
		s.k.Close()
	}
}

func NewTextResult(content string, err error) *mcp.CallToolResult {
	if err != nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: err.Error(),
				},
			},
		}
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: content,
			},
		},
	}
}

func contextFunc(ctx context.Context, r *http.Request) context.Context {
	//return context.WithValue(ctx, kubernetes.AuthorizationHeader, r.Header.Get(kubernetes.AuthorizationHeader))
	return context.WithValue(ctx, kubernetes.AuthorizationBearerTokenHeader, r.Header.Get(kubernetes.AuthorizationBearerTokenHeader))
}
