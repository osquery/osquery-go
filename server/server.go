package server

import (
	"fmt"
	"net"
	"time"

	"git.apache.org/thrift.git/lib/go/thrift"

	"github.com/kolide/osquery-golang/client"
	"github.com/kolide/osquery-golang/gen/osquery"
	"github.com/pkg/errors"
)

type OsqueryPlugin interface {
	Name() string
	RegistryName() string
	Routes() osquery.ExtensionPluginResponse
	Ping() osquery.ExtensionStatus
	Call(osquery.ExtensionPluginRequest) osquery.ExtensionResponse
	Shutdown()
}

type ExtensionManagerServer struct {
	name         string
	sockPath     string
	serverClient *client.ExtensionManagerClient
	registry     map[string](map[string]OsqueryPlugin)
	server       thrift.TServer
	transport    thrift.TServerTransport
}

func NewExtensionManagerServer(name string, sockPath string, timeout time.Duration) (*ExtensionManagerServer, error) {
	serverClient, err := client.NewClient(sockPath, timeout)
	if err != nil {
		return nil, err
	}
	return &ExtensionManagerServer{
		name:         name,
		sockPath:     sockPath,
		serverClient: serverClient,
		registry:     make(map[string](map[string]OsqueryPlugin)),
	}, nil
}

func (s *ExtensionManagerServer) RegisterPlugin(plugin OsqueryPlugin) {
	if s.registry[plugin.RegistryName()] == nil {
		s.registry[plugin.RegistryName()] = make(map[string]OsqueryPlugin)
	}
	s.registry[plugin.RegistryName()][plugin.Name()] = plugin
}

func (s *ExtensionManagerServer) genRegistry() osquery.ExtensionRegistry {
	registry := osquery.ExtensionRegistry{}
	for regName, _ := range s.registry {
		registry[regName] = osquery.ExtensionRouteTable{}
		for _, plugin := range s.registry[regName] {
			registry[regName][plugin.Name()] = plugin.Routes()
		}
	}
	return registry
}

func (s *ExtensionManagerServer) Start() error {
	registry := s.genRegistry()

	stat, err := s.serverClient.RegisterExtension(
		&osquery.InternalExtensionInfo{
			Name: s.name,
		},
		registry,
	)
	if err != nil {
		return errors.Wrap(err, "registering extension")
	}
	if stat.Code != 0 {
		return errors.Errorf("status %d registering extension: %s", stat.Code, stat.Message)
	}

	listenPath := fmt.Sprintf("%s.%d", s.sockPath, stat.UUID)

	addr, err := net.ResolveUnixAddr("unix", listenPath)
	if err != nil {
		return errors.Wrapf(err, "resolving addr (%s)", addr)
	}

	processor := osquery.NewExtensionProcessor(s)

	s.transport = thrift.NewTServerSocketFromAddrTimeout(addr, 0)
	if err != nil {
		return errors.Wrapf(err, "opening server socket (%s)", addr)
	}

	s.server = thrift.NewTSimpleServer2(processor, s.transport)

	return s.server.Serve()
}

func (s *ExtensionManagerServer) Ping() (*osquery.ExtensionStatus, error) {
	return &osquery.ExtensionStatus{Code: 0, Message: "OK"}, nil
}

func (s *ExtensionManagerServer) Call(registry string, item string, request osquery.ExtensionPluginRequest) (*osquery.ExtensionResponse, error) {
	subreg, ok := s.registry[registry]
	if !ok {
		return &osquery.ExtensionResponse{
			Status: &osquery.ExtensionStatus{
				Code:    1,
				Message: "Unknown registry: " + registry,
			},
		}, nil
	}

	plugin, ok := subreg[item]
	if !ok {
		return &osquery.ExtensionResponse{
			Status: &osquery.ExtensionStatus{
				Code:    1,
				Message: "Unknown registry item: " + item,
			},
		}, nil
	}

	response := plugin.Call(request)
	return &response, nil
}

func (s *ExtensionManagerServer) Shutdown() error {
	if s.server != nil {
		err := s.server.Stop()
		if err != nil {
			return err
		}
	}
	if s.transport != nil {
		return s.transport.Close()
	}
	return nil
}
