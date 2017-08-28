package distributed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/kolide/osquery-go/gen/osquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var StatusOK = osquery.ExtensionStatus{Code: 0, Message: "OK"}

func TestDistributedPlugin(t *testing.T) {
	var getCalled, writeCalled bool
	var results []Result
	plugin := NewPlugin(
		"mock",
		func(context.Context) (*GetQueriesResult, error) {
			getCalled = true
			return &GetQueriesResult{
				Queries: map[string]string{
					"query1": "select iso_8601 from time",
					"query2": "select version from osquery_info",
					"query3": "select foo from bar",
				},
			}, nil
		},
		func(ctx context.Context, res []Result) error {
			writeCalled = true
			results = res
			return nil
		},
	)

	// Basic methods
	assert.Equal(t, "distributed", plugin.RegistryName())
	assert.Equal(t, "mock", plugin.Name())
	assert.Equal(t, StatusOK, plugin.Ping())
	assert.Equal(t, osquery.ExtensionPluginResponse{}, plugin.Routes())

	// Call getQueries
	resp := plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "getQueries"})
	assert.True(t, getCalled)
	assert.False(t, writeCalled)
	assert.Equal(t, &StatusOK, resp.Status)
	if assert.Len(t, resp.Response, 1) {
		assert.JSONEq(t, `{"queries": {"query1": "select iso_8601 from time", "query2": "select version from osquery_info", "query3": "select foo from bar"}}`,
			resp.Response[0]["results"])
	}

	// Call writeResults
	getCalled = false
	resp = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "writeResults", "results": `{"queries":{"query1":[{"iso_8601":"2017-07-10T22:08:40Z"}],"query2":[{"version":"2.4.0"}]},"statuses":{"query1":"0","query2":"0","query3":"1"}}`})
	assert.False(t, getCalled)
	assert.True(t, writeCalled)
	assert.Equal(t, &StatusOK, resp.Status)
	// Ensure correct ordering for comparison
	sort.Slice(results, func(i, j int) bool { return results[i].QueryName < results[j].QueryName })
	assert.Equal(t, []Result{
		{"query1", 0, []map[string]string{{"iso_8601": "2017-07-10T22:08:40Z"}}},
		{"query2", 0, []map[string]string{{"version": "2.4.0"}}},
		{"query3", 1, []map[string]string{}},
	},
		results)
}

func TestDistributedPluginAccelerateDiscovery(t *testing.T) {
	plugin := NewPlugin(
		"mock",
		func(context.Context) (*GetQueriesResult, error) {
			return &GetQueriesResult{
				Queries: map[string]string{
					"query1": "select * from time",
				},
				Discovery: map[string]string{
					"query1": `select version from osquery_info where version = "2.4.0"`,
				},
				AccelerateSeconds: 30,
			}, nil
		},
		func(ctx context.Context, res []Result) error {
			return nil
		},
	)

	// Call getQueries
	resp := plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "getQueries"})
	assert.Equal(t, &StatusOK, resp.Status)
	if assert.Len(t, resp.Response, 1) {
		assert.JSONEq(t, `{"queries": {"query1": "select * from time"}, "discovery": {"query1": "select version from osquery_info where version = \"2.4.0\""}, "accelerate": 30}`,
			resp.Response[0]["results"])
	}
}

func TestDistributedPluginErrors(t *testing.T) {
	var getCalled, writeCalled bool
	plugin := NewPlugin(
		"mock",
		func(context.Context) (*GetQueriesResult, error) {
			getCalled = true
			return nil, errors.New("getQueries failed")
		},
		func(ctx context.Context, res []Result) error {
			writeCalled = true
			return errors.New("writeResults failed")
		},
	)

	// Call with bad actions
	assert.Equal(t, int32(1), plugin.Call(context.Background(), osquery.ExtensionPluginRequest{}).Status.Code)
	assert.False(t, getCalled)
	assert.False(t, writeCalled)
	assert.Equal(t, int32(1), plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "bad"}).Status.Code)
	assert.False(t, getCalled)
	assert.False(t, writeCalled)

	// Call with good action but getQueries fails
	resp := plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "getQueries"})
	assert.True(t, getCalled)
	assert.False(t, writeCalled)
	assert.Equal(t, int32(1), resp.Status.Code)
	assert.Equal(t, "error getting queries: getQueries failed", resp.Status.Message)

	getCalled = false

	// Call with good action but writeResults fails
	// Error unmarshalling results
	resp = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "writeResults", "results": "foobar"})
	assert.False(t, getCalled)
	assert.False(t, writeCalled)
	assert.Equal(t, int32(1), resp.Status.Code)
	assert.Contains(t, resp.Status.Message, "error unmarshalling results")

	// Error converting status
	resp = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "writeResults", "results": `{"statuses": {"query1": "foo"}}`})
	assert.False(t, getCalled)
	assert.False(t, writeCalled)
	assert.Equal(t, int32(1), resp.Status.Code)
	assert.Contains(t, resp.Status.Message, `error unmarshalling results: json: cannot unmarshal`)

	// Error unmarshalling results
	resp = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "writeResults", "results": "{}"})
	assert.False(t, getCalled)
	assert.True(t, writeCalled)
	assert.Equal(t, int32(1), resp.Status.Code)
	assert.Contains(t, resp.Status.Message, "error writing results")
}

var rawJsonQuery = "{\"queries\":{\"kolide_detail_query_network_interface\":[{\"interface\":\"en0\",\"mac\":\"78:4f:43:9c:3c:8d\",\"type\":\"\",\"mtu\":\"1500\",\"metric\":\"0\",\"ipackets\":\"7071136\",\"opackets\":\"6408727\",\"ibytes\":\"1481456771\",\"obytes\":\"1633052673\",\"ierrors\":\"0\",\"oerrors\":\"0\",\"idrops\":\"0\",\"odrops\":\"0\",\"last_change\":\"1501077669\",\"description\":\"\",\"manufacturer\":\"\",\"connection_id\":\"\",\"connection_status\":\"\",\"enabled\":\"\",\"physical_adapter\":\"\",\"speed\":\"\",\"dhcp_enabled\":\"\",\"dhcp_lease_expires\":\"\",\"dhcp_lease_obtained\":\"\",\"dhcp_server\":\"\",\"dns_domain\":\"\",\"dns_domain_suffix_search_order\":\"\",\"dns_host_name\":\"\",\"dns_server_search_order\":\"\",\"interface\":\"en0\",\"address\":\"192.168.1.135\",\"mask\":\"255.255.255.0\",\"broadcast\":\"192.168.1.255\",\"point_to_point\":\"\",\"type\":\"\"}],\"kolide_detail_query_os_version\":[{\"name\":\"Mac OS X\",\"version\":\"10.12.6\",\"major\":\"10\",\"minor\":\"12\",\"patch\":\"6\",\"build\":\"16G29\",\"platform\":\"darwin\",\"platform_like\":\"darwin\",\"codename\":\"\"}],\"kolide_detail_query_osquery_flags\":[{\"name\":\"config_refresh\",\"value\":\"10\"},{\"name\":\"distributed_interval\",\"value\":\"10\"},{\"name\":\"logger_tls_period\",\"value\":\"10\"}],\"kolide_detail_query_osquery_info\":[{\"pid\":\"75680\",\"uuid\":\"DE56C776-2F5A-56DF-81C7-F64EE1BBEC8C\",\"instance_id\":\"89f267fa-9a17-4a73-87d6-05197491f2e8\",\"version\":\"2.5.0\",\"config_hash\":\"960121acb9bcbb136ce49fe77000752f237fd0dd\",\"config_valid\":\"1\",\"extensions\":\"active\",\"build_platform\":\"darwin\",\"build_distro\":\"10.12\",\"start_time\":\"1502371429\",\"watcher\":\"75678\"}],\"kolide_detail_query_system_info\":[{\"hostname\":\"Johns-MacBook-Pro.local\",\"uuid\":\"DE56C776-2F5A-56DF-81C7-F64EE1BBEC8C\",\"cpu_type\":\"x86_64h\",\"cpu_subtype\":\"Intel x86-64h Haswell\",\"cpu_brand\":\"Intel(R) Core(TM) i7-6820HQ CPU @ 2.70GHz\",\"cpu_physical_cores\":\"4\",\"cpu_logical_cores\":\"8\",\"physical_memory\":\"17179869184\",\"hardware_vendor\":\"Apple Inc.\",\"hardware_model\":\"MacBookPro13,3\",\"hardware_version\":\"1.0\",\"hardware_serial\":\"C02SP067H040\",\"computer_name\":\"\",\"local_hostname\":\"Johns-MacBook-Pro\"}],\"kolide_detail_query_uptime\":[{\"days\":\"21\",\"hours\":\"18\",\"minutes\":\"44\",\"seconds\":\"28\",\"total_seconds\":\"1881868\"}],\"kolide_label_query_6\":[{\"1\":\"1\"}],\"kolide_label_query_9\":\"\",\"kolide_detail_query_network_interface\":[{\"interface\":\"en0\",\"mac\":\"78:4f:43:9c:3c:8d\",\"type\":\"\",\"mtu\":\"1500\",\"metric\":\"0\",\"ipackets\":\"7071178\",\"opackets\":\"6408775\",\"ibytes\":\"1481473778\",\"obytes\":\"1633061382\",\"ierrors\":\"0\",\"oerrors\":\"0\",\"idrops\":\"0\",\"odrops\":\"0\",\"last_change\":\"1501077680\",\"description\":\"\",\"manufacturer\":\"\",\"connection_id\":\"\",\"connection_status\":\"\",\"enabled\":\"\",\"physical_adapter\":\"\",\"speed\":\"\",\"dhcp_enabled\":\"\",\"dhcp_lease_expires\":\"\",\"dhcp_lease_obtained\":\"\",\"dhcp_server\":\"\",\"dns_domain\":\"\",\"dns_domain_suffix_search_order\":\"\",\"dns_host_name\":\"\",\"dns_server_search_order\":\"\",\"interface\":\"en0\",\"address\":\"192.168.1.135\",\"mask\":\"255.255.255.0\",\"broadcast\":\"192.168.1.255\",\"point_to_point\":\"\",\"type\":\"\"}],\"kolide_detail_query_os_version\":[{\"name\":\"Mac OS X\",\"version\":\"10.12.6\",\"major\":\"10\",\"minor\":\"12\",\"patch\":\"6\",\"build\":\"16G29\",\"platform\":\"darwin\",\"platform_like\":\"darwin\",\"codename\":\"\"}],\"kolide_detail_query_osquery_flags\":[{\"name\":\"config_refresh\",\"value\":\"10\"},{\"name\":\"distributed_interval\",\"value\":\"10\"},{\"name\":\"logger_tls_period\",\"value\":\"10\"}],\"kolide_detail_query_osquery_info\":[{\"pid\":\"75680\",\"uuid\":\"DE56C776-2F5A-56DF-81C7-F64EE1BBEC8C\",\"instance_id\":\"89f267fa-9a17-4a73-87d6-05197491f2e8\",\"version\":\"2.5.0\",\"config_hash\":\"960121acb9bcbb136ce49fe77000752f237fd0dd\",\"config_valid\":\"1\",\"extensions\":\"active\",\"build_platform\":\"darwin\",\"build_distro\":\"10.12\",\"start_time\":\"1502371429\",\"watcher\":\"75678\"}],\"kolide_detail_query_system_info\":[{\"hostname\":\"Johns-MacBook-Pro.local\",\"uuid\":\"DE56C776-2F5A-56DF-81C7-F64EE1BBEC8C\",\"cpu_type\":\"x86_64h\",\"cpu_subtype\":\"Intel x86-64h Haswell\",\"cpu_brand\":\"Intel(R) Core(TM) i7-6820HQ CPU @ 2.70GHz\",\"cpu_physical_cores\":\"4\",\"cpu_logical_cores\":\"8\",\"physical_memory\":\"17179869184\",\"hardware_vendor\":\"Apple Inc.\",\"hardware_model\":\"MacBookPro13,3\",\"hardware_version\":\"1.0\",\"hardware_serial\":\"C02SP067H040\",\"computer_name\":\"\",\"local_hostname\":\"Johns-MacBook-Pro\"}],\"kolide_detail_query_uptime\":[{\"days\":\"21\",\"hours\":\"18\",\"minutes\":\"44\",\"seconds\":\"38\",\"total_seconds\":\"1881878\"}],\"kolide_label_query_6\":[{\"1\":\"1\"}],\"kolide_label_query_9\":\"\",\"kolide_detail_query_network_interface\":[{\"interface\":\"en0\",\"mac\":\"78:4f:43:9c:3c:8d\",\"type\":\"\",\"mtu\":\"1500\",\"metric\":\"0\",\"ipackets\":\"7071216\",\"opackets\":\"6408814\",\"ibytes\":\"1481486677\",\"obytes\":\"1633066361\",\"ierrors\":\"0\",\"oerrors\":\"0\",\"idrops\":\"0\",\"odrops\":\"0\",\"last_change\":\"1501077688\",\"description\":\"\",\"manufacturer\":\"\",\"connection_id\":\"\",\"connection_status\":\"\",\"enabled\":\"\",\"physical_adapter\":\"\",\"speed\":\"\",\"dhcp_enabled\":\"\",\"dhcp_lease_expires\":\"\",\"dhcp_lease_obtained\":\"\",\"dhcp_server\":\"\",\"dns_domain\":\"\",\"dns_domain_suffix_search_order\":\"\",\"dns_host_name\":\"\",\"dns_server_search_order\":\"\",\"interface\":\"en0\",\"address\":\"192.168.1.135\",\"mask\":\"255.255.255.0\",\"broadcast\":\"192.168.1.255\",\"point_to_point\":\"\",\"type\":\"\"}],\"kolide_detail_query_os_version\":[{\"name\":\"Mac OS X\",\"version\":\"10.12.6\",\"major\":\"10\",\"minor\":\"12\",\"patch\":\"6\",\"build\":\"16G29\",\"platform\":\"darwin\",\"platform_like\":\"darwin\",\"codename\":\"\"}],\"kolide_detail_query_osquery_flags\":[{\"name\":\"config_refresh\",\"value\":\"10\"},{\"name\":\"distributed_interval\",\"value\":\"10\"},{\"name\":\"logger_tls_period\",\"value\":\"10\"}],\"kolide_detail_query_osquery_info\":[{\"pid\":\"75680\",\"uuid\":\"DE56C776-2F5A-56DF-81C7-F64EE1BBEC8C\",\"instance_id\":\"89f267fa-9a17-4a73-87d6-05197491f2e8\",\"version\":\"2.5.0\",\"config_hash\":\"960121acb9bcbb136ce49fe77000752f237fd0dd\",\"config_valid\":\"1\",\"extensions\":\"active\",\"build_platform\":\"darwin\",\"build_distro\":\"10.12\",\"start_time\":\"1502371429\",\"watcher\":\"75678\"}],\"kolide_detail_query_system_info\":[{\"hostname\":\"Johns-MacBook-Pro.local\",\"uuid\":\"DE56C776-2F5A-56DF-81C7-F64EE1BBEC8C\",\"cpu_type\":\"x86_64h\",\"cpu_subtype\":\"Intel x86-64h Haswell\",\"cpu_brand\":\"Intel(R) Core(TM) i7-6820HQ CPU @ 2.70GHz\",\"cpu_physical_cores\":\"4\",\"cpu_logical_cores\":\"8\",\"physical_memory\":\"17179869184\",\"hardware_vendor\":\"Apple Inc.\",\"hardware_model\":\"MacBookPro13,3\",\"hardware_version\":\"1.0\",\"hardware_serial\":\"C02SP067H040\",\"computer_name\":\"\",\"local_hostname\":\"Johns-MacBook-Pro\"}],\"kolide_detail_query_uptime\":[{\"days\":\"21\",\"hours\":\"18\",\"minutes\":\"44\",\"seconds\":\"49\",\"total_seconds\":\"1881889\"}],\"kolide_label_query_6\":[{\"1\":\"1\"}],\"kolide_label_query_9\":\"\"},\"statuses\":{\"kolide_detail_query_network_interface\":\"0\",\"kolide_detail_query_os_version\":\"0\",\"kolide_detail_query_osquery_flags\":\"0\",\"kolide_detail_query_osquery_info\":\"0\",\"kolide_detail_query_system_info\":\"0\",\"kolide_detail_query_uptime\":\"0\",\"kolide_label_query_6\":\"0\",\"kolide_label_query_9\":\"0\"}}\n"

func TestUnmarshalResults(t *testing.T) {
	var rs ResultsStruct
	err := json.NewDecoder(bytes.NewBufferString(rawJsonQuery)).Decode(&rs)
	require.Nil(t, err)
	results, err := rs.toResults()
	require.Nil(t, err)
	assert.Len(t, results, 8)
}

func TestUnmarshalStatus(t *testing.T) {
	testCases := []struct {
		json     []byte
		success  bool
		expected OsqueryInt
	}{
		{[]byte{}, true, 0},
		{[]byte(`""`), true, 0},
		{[]byte(`"23"`), true, 23},
		{[]byte(`"0000"`), true, 0},
		{[]byte(`"-12"`), true, -12},
		{[]byte(`"0"`), true, 0},
		{[]byte(`"foo"`), false, 0},
		{[]byte(`0`), true, 0},
		{[]byte(`1`), true, 1},
	}
	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("#%.2d", i), func(t *testing.T) {
			var i OsqueryInt
			err := i.UnmarshalJSON(testCase.json)
			require.Equal(t, testCase.success, (err == nil), fmt.Sprintf("Trying to convert %s", string(testCase.json)))
			assert.Equal(t, testCase.expected, i)
		})
	}
}

func TestHandleResults(t *testing.T) {
	called := false
	var results []Result
	plugin := NewPlugin(
		"mock",
		nil,
		func(ctx context.Context, res []Result) error {
			called = true
			results = res
			return nil
		},
	)
	resp := plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "writeResults", "results": rawJsonQuery})
	require.True(t, called)
	assert.Len(t, results, 8)
	assert.Equal(t, &StatusOK, resp.Status)
}
