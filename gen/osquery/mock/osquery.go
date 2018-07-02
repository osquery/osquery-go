// Automatically generated by mockimpl. DO NOT EDIT!

package mock

import "github.com/kolide/osquery-go/gen/osquery"

var _ osquery.ExtensionManager = (*ExtensionManager)(nil)

type CloseFunc func()

type PingFunc func() (*osquery.ExtensionStatus, error)

type CallFunc func(registry string, item string, req osquery.ExtensionPluginRequest) (*osquery.ExtensionResponse, error)

type ShutdownFunc func() error

type ExtensionsFunc func() (osquery.InternalExtensionList, error)

type RegisterExtensionFunc func(info *osquery.InternalExtensionInfo, registry osquery.ExtensionRegistry) (*osquery.ExtensionStatus, error)

type DeregisterExtensionFunc func(uuid osquery.ExtensionRouteUUID) (*osquery.ExtensionStatus, error)

type OptionsFunc func() (osquery.InternalOptionList, error)

type QueryFunc func(sql string) (*osquery.ExtensionResponse, error)

type GetQueryColumnsFunc func(sql string) (*osquery.ExtensionResponse, error)

type ExtensionManager struct {
	CloseFunc        CloseFunc
	CloseFuncInvoked bool

	PingFunc        PingFunc
	PingFuncInvoked bool

	CallFunc        CallFunc
	CallFuncInvoked bool

	ShutdownFunc        ShutdownFunc
	ShutdownFuncInvoked bool

	ExtensionsFunc        ExtensionsFunc
	ExtensionsFuncInvoked bool

	RegisterExtensionFunc        RegisterExtensionFunc
	RegisterExtensionFuncInvoked bool

	DeregisterExtensionFunc        DeregisterExtensionFunc
	DeregisterExtensionFuncInvoked bool

	OptionsFunc        OptionsFunc
	OptionsFuncInvoked bool

	QueryFunc        QueryFunc
	QueryFuncInvoked bool

	GetQueryColumnsFunc        GetQueryColumnsFunc
	GetQueryColumnsFuncInvoked bool
}

func (m *ExtensionManager) Close() {
	m.CloseFuncInvoked = true
	m.CloseFunc()
}

func (m *ExtensionManager) Ping() (*osquery.ExtensionStatus, error) {
	m.PingFuncInvoked = true
	return m.PingFunc()
}

func (m *ExtensionManager) Call(registry string, item string, req osquery.ExtensionPluginRequest) (*osquery.ExtensionResponse, error) {
	m.CallFuncInvoked = true
	return m.CallFunc(registry, item, req)
}

func (m *ExtensionManager) Shutdown() error {
	m.ShutdownFuncInvoked = true
	return m.ShutdownFunc()
}

func (m *ExtensionManager) Extensions() (osquery.InternalExtensionList, error) {
	m.ExtensionsFuncInvoked = true
	return m.ExtensionsFunc()
}

func (m *ExtensionManager) RegisterExtension(info *osquery.InternalExtensionInfo, registry osquery.ExtensionRegistry) (*osquery.ExtensionStatus, error) {
	m.RegisterExtensionFuncInvoked = true
	return m.RegisterExtensionFunc(info, registry)
}

func (m *ExtensionManager) DeregisterExtension(uuid osquery.ExtensionRouteUUID) (*osquery.ExtensionStatus, error) {
	m.DeregisterExtensionFuncInvoked = true
	return m.DeregisterExtensionFunc(uuid)
}

func (m *ExtensionManager) Options() (osquery.InternalOptionList, error) {
	m.OptionsFuncInvoked = true
	return m.OptionsFunc()
}

func (m *ExtensionManager) Query(sql string) (*osquery.ExtensionResponse, error) {
	m.QueryFuncInvoked = true
	return m.QueryFunc(sql)
}

func (m *ExtensionManager) GetQueryColumns(sql string) (*osquery.ExtensionResponse, error) {
	m.GetQueryColumnsFuncInvoked = true
	return m.GetQueryColumnsFunc(sql)
}
