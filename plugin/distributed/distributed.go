// Package distributed creates an osquery distributed query plugin.
package distributed

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/kolide/osquery-go/gen/osquery"
)

// GetQueriesFunc returns the queries that should be executed.
// The returned map should include the query name as the keys, and the query
// text as values. Results will be returned corresponding to the provided name.
// The context argument can optionally be used for cancellation in long-running
// operations.
type GetQueriesFunc func(ctx context.Context) (map[string]string, error)

// Result contains the status and results for a distributed query.
type Result struct {
	// QueryName is the name that was originally provided for the query.
	QueryName string
	// Status is an integer status code for the query execution (0 = OK)
	Status int
	// Rows is the result rows of the query.
	Rows []map[string]string
}

// WriteResultsFunc writes the results of the executed distributed queries. The
// query results will be serialized JSON in the results map with the query name
// as the key.
type WriteResultsFunc func(ctx context.Context, results []Result) error

// Plugin is an osquery configuration plugin. Plugin implements the OsqueryPlugin
// interface.
type Plugin struct {
	name         string
	getQueries   GetQueriesFunc
	writeResults WriteResultsFunc
}

// NewPlugin takes the distributed query functions and returns a struct
// implementing the OsqueryPlugin interface. Use this to wrap the appropriate
// functions into an osquery plugin.
func NewPlugin(name string, getQueries GetQueriesFunc, writeResults WriteResultsFunc) *Plugin {
	return &Plugin{name: name, getQueries: getQueries, writeResults: writeResults}
}

func (t *Plugin) Name() string {
	return t.name
}

// Registry name for distributed plugins
const distributedRegistryName = "distributed"

func (t *Plugin) RegistryName() string {
	return distributedRegistryName
}

func (t *Plugin) Routes() osquery.ExtensionPluginResponse {
	return osquery.ExtensionPluginResponse{}
}

func (t *Plugin) Ping() osquery.ExtensionStatus {
	return osquery.ExtensionStatus{Code: 0, Message: "OK"}
}

// Key that the request method is stored under
const requestActionKey = "action"

// Action value used when queries are requested
const getQueriesAction = "getQueries"

// Action value used when results are written
const writeResultsAction = "writeResults"

// Key that results are stored under
const requestResultKey = "results"

type resultsStruct struct {
	Queries  map[string][]map[string]string `json:"queries"`
	Statuses map[string]string              `json:"statuses"`
}

func (t *Plugin) Call(ctx context.Context, request osquery.ExtensionPluginRequest) osquery.ExtensionResponse {
	switch request[requestActionKey] {
	case getQueriesAction:
		queries, err := t.getQueries(ctx)
		if err != nil {
			return osquery.ExtensionResponse{
				Status: &osquery.ExtensionStatus{
					Code:    1,
					Message: "error getting queries: " + err.Error(),
				},
			}
		}

		queryJSON, err := json.Marshal(map[string](map[string]string){"queries": queries})
		if err != nil {
			return osquery.ExtensionResponse{
				Status: &osquery.ExtensionStatus{
					Code:    1,
					Message: "error marshalling queries: " + err.Error(),
				},
			}
		}

		return osquery.ExtensionResponse{
			Status:   &osquery.ExtensionStatus{Code: 0, Message: "OK"},
			Response: osquery.ExtensionPluginResponse{map[string]string{"results": string(queryJSON)}},
		}

	case writeResultsAction:
		var res resultsStruct
		err := json.Unmarshal([]byte(request[requestResultKey]), &res)

		if err != nil {
			return osquery.ExtensionResponse{
				Status: &osquery.ExtensionStatus{
					Code:    1,
					Message: "error unmarshalling results: " + err.Error(),
				},
			}
		}

		// Rewrite the results to a more sane format than that provided
		// by osquery
		var results []Result
		for name, rows := range res.Queries {
			status, err := strconv.Atoi(res.Statuses[name])
			if err != nil {
				return osquery.ExtensionResponse{
					Status: &osquery.ExtensionStatus{
						Code:    1,
						Message: "invalid status for query " + name + ": " + err.Error(),
					},
				}
			}

			results = append(results, Result{QueryName: name, Status: status, Rows: rows})
		}

		err = t.writeResults(ctx, results)
		if err != nil {
			return osquery.ExtensionResponse{
				Status: &osquery.ExtensionStatus{
					Code:    1,
					Message: "error writing results: " + err.Error(),
				},
			}
		}

		return osquery.ExtensionResponse{
			Status:   &osquery.ExtensionStatus{Code: 0, Message: "OK"},
			Response: osquery.ExtensionPluginResponse{},
		}

	default:
		return osquery.ExtensionResponse{
			Status: &osquery.ExtensionStatus{
				Code:    1,
				Message: "unknown action: " + request["action"],
			},
		}
	}

}

func (t *Plugin) Shutdown() {}
