package osquery

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"git.apache.org/thrift.git/lib/go/thrift"

	"github.com/kolide/osquery-go/gen/osquery"
	"github.com/pkg/errors"
)

type OsqueryPlugin interface {
	// Name is the name used to refer to the plugin (eg. the name of the
	// table the plugin implements).
	Name() string
	// RegistryName is which "registry" the plugin should be added to.
	// Valid names are ["config", "logger", "table"].
	RegistryName() string
	// Routes returns the detailed information about the interface exposed
	// by the plugin. See the example plugins for samples.
	Routes() osquery.ExtensionPluginResponse
	// Ping implements a health check for the plugin. If the plugin is in a
	// healthy state, StatusOK should be returned.
	Ping() osquery.ExtensionStatus
	// Call requests the plugin to perform its defined behavior, returning
	// a response containing the result.
	Call(context.Context, osquery.ExtensionPluginRequest) osquery.ExtensionResponse
	// Shutdown alerts the plugin to stop.
	Shutdown()
}

const defaultTimeout = 1 * time.Second

// ExtensionManagerServer is an implementation of the full ExtensionManager
// API. Plugins can register with an extension manager, which handles the
// communication with the osquery process.
type ExtensionManagerServer struct {
	name         string
	sockPath     string
	serverClient *ExtensionManagerClient
	registry     map[string](map[string]OsqueryPlugin)
	server       thrift.TServer
	transport    thrift.TServerTransport
	timeout      time.Duration
}

// validRegistryNames contains the allowable RegistryName() values. If a plugin
// attempts to register with another value, the program will panic.
var validRegistryNames = map[string]bool{
	"table":  true,
	"logger": true,
	"config": true,
}

type ServerOption func(*ExtensionManagerServer)

func ServerTimeout(timeout time.Duration) ServerOption {
	return func(s *ExtensionManagerServer) {
		s.timeout = timeout
	}
}

// NewExtensionManagerServer creates a new extension management server
// communicating with osquery over the socket at the provided path. If
// resolving the address or connecting to the socket fails, this function will
// error.
func NewExtensionManagerServer(name string, sockPath string, opts ...ServerOption) (*ExtensionManagerServer, error) {
	// Initialize nested registry maps
	registry := make(map[string](map[string]OsqueryPlugin))
	for reg, _ := range validRegistryNames {
		registry[reg] = make(map[string]OsqueryPlugin)
	}

	manager := &ExtensionManagerServer{
		name:     name,
		sockPath: sockPath,
		registry: registry,
		timeout:  defaultTimeout,
	}

	for _, opt := range opts {
		opt(manager)
	}

	serverClient, err := NewClient(sockPath, manager.timeout)
	if err != nil {
		return nil, err
	}
	manager.serverClient = serverClient

	return manager, nil
}

// RegisterPlugin adds an OsqueryPlugin to this extension manager.
func (s *ExtensionManagerServer) RegisterPlugin(plugin OsqueryPlugin) {
	if !validRegistryNames[plugin.RegistryName()] {
		panic("invalid registry name: " + plugin.RegistryName())
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

// Start registers the extension plugins and begins listening on a unix socket
// for requests from the osquery process. All plugins should be registered with
// RegisterPlugin() before calling Start().
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

// Run starts the extension manager and runs until an an interrupt
// signal is received.
// Run will call Shutdown before exiting.
func (s *ExtensionManagerServer) Run() error {
	errc := make(chan error)
	go func() {
		errc <- s.Start()
	}()

	// Interrupt handler.
	go func() {
		sig := make(chan os.Signal)
		signal.Notify(sig, os.Interrupt, os.Kill, syscall.SIGTERM)
		<-sig
		errc <- nil
	}()

	err := <-errc
	if err != nil {
		return err
	}

	return s.Shutdown()
}

// Ping implements the basic health check.
func (s *ExtensionManagerServer) Ping() (*osquery.ExtensionStatus, error) {
	return &osquery.ExtensionStatus{Code: 0, Message: "OK"}, nil
}

// Call routes a call from the osquery process to the appropriate registered
// plugin.
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

	response := plugin.Call(context.Background(), request)
	return &response, nil
}

// Shutdown stops the server and closes the listening socket.
func (s *ExtensionManagerServer) Shutdown() error {
	defer func() {
		s.server = nil
	}()
	if s.server != nil {
		err := s.server.Stop()
		if err != nil {
			return errors.Wrap(err, "stopping server")
		}
	}

	defer func() {
		s.transport = nil
	}()
	if s.transport != nil {
		err := s.transport.Close()
		if err != nil {
			return errors.Wrap(err, "closing transport")
		}
	}

	return nil
}
