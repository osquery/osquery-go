// Package distributed creates an osquery distributed query plugin.
package distributed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/kolide/osquery-go/gen/osquery"
)

// GetQueriesResult contains the information about which queries the
// distributed system should run.
type GetQueriesResult struct {
	// Queries is a map from query name to query SQL
	Queries map[string]string `json:"queries"`
	// Discovery is used for "discovery" queries in the distributed
	// system. When used, discovery queries should be specified with query
	// name as the key and the discover query SQL as the value. If this is
	// nonempty, only queries for which the associated discovery query
	// returns results will be run in osquery.
	Discovery map[string]string `json:"discovery,omitempty"`
	// AccelerateSeconds can be specified to have "accelerated" checkins
	// for a given number of seconds after this checkin. Currently this
	// means that checkins will occur every 5 seconds.
	AccelerateSeconds int `json:"accelerate,omitempty"`
}

// GetQueriesFunc returns the queries that should be executed.
// The returned map should include the query name as the keys, and the query
// text as values. Results will be returned corresponding to the provided name.
// The context argument can optionally be used for cancellation in long-running
// operations.
type GetQueriesFunc func(ctx context.Context) (*GetQueriesResult, error)

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

// Just used for unmarshalling the results passed from osquery.
type resultsStruct struct {
	Queries  map[string][]map[string]string `json:"queries"`
	Statuses map[string]string              `json:"statuses"`
}

func convertRows(rows []interface{}) ([]map[string]string, error) {
	var results []map[string]string
	for _, intf := range rows {
		row, ok := intf.(map[string]interface{})
		if !ok {
			return nil, errors.New("invalid row type for query")
		}
		result := make(map[string]string)
		for col, val := range row {
			sval, ok := val.(string)
			if !ok {
				return nil, fmt.Errorf("invalid type for col %q", col)
			}
			result[col] = sval
		}
		results = append(results, result)
	}
	return results, nil
}

func parseResults(jsn string) ([]Result, error) {
	// Queries can be []map[string]string OR an empty string
	// so we need to deal with an interface to accomodate two types
	intermediate := struct {
		Queries  map[string]interface{} `json:"queries"`
		Statuses map[string]string      `json:"statuses"`
	}{}
	if err := json.NewDecoder(bytes.NewBufferString(jsn)).Decode(&intermediate); err != nil {
		return nil, err
	}
	var results []Result
	for queryName, status := range intermediate.Statuses {
		var result Result
		result.QueryName = queryName
		statVal, err := strconv.Atoi(status)
		if err != nil {
			return nil, errors.New("invalid status")
		}
		result.Status = statVal
		query, ok := intermediate.Queries[queryName]
		// if query rows aren't present we are done, get next status/query
		if !ok {
			result.Rows = []map[string]string{}
			results = append(results, result)
			continue
		}
		// if query is present, deal with structural inconsistency it may be a string
		// or an array of maps representing each row in result
		switch val := query.(type) {
		case string:
			result.Rows = []map[string]string{}
		case []interface{}:
			rows, err := convertRows(val)
			if err != nil {
				return nil, err
			}
			result.Rows = rows
		default:
			return nil, errors.New("query type is not valid")
		}

		results = append(results, result)
	}
	return results, nil
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

		queryJSON, err := json.Marshal(queries)
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
		results, err := parseResults(request[requestResultKey])
		if err != nil {
			return osquery.ExtensionResponse{
				Status: &osquery.ExtensionStatus{
					Code:    1,
					Message: "error unmarshalling results: " + err.Error(),
				},
			}
		}
		// invoke callback
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
