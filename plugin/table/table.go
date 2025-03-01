// Package table creates an osquery table plugin.
package table

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/osquery/osquery-go/gen/osquery"
	"github.com/osquery/osquery-go/traces"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/codes"
)

// Generate returns the rows generated by the table. The ctx argument
// should be checked for cancellation if the generation performs a
// substantial amount of work. The queryContext argument provides the
// deserialized JSON query context from osquery.
type GenerateFunc func(ctx context.Context, queryContext QueryContext) ([]map[string]string, error)

type Plugin struct {
	name     string
	columns  []ColumnDefinition
	generate GenerateFunc
}

func NewPlugin(name string, columns []ColumnDefinition, gen GenerateFunc) *Plugin {
	return &Plugin{
		name:     name,
		columns:  columns,
		generate: gen,
	}
}

func (t *Plugin) Name() string {
	return t.name
}

func (t *Plugin) RegistryName() string {
	return "table"
}

func (t *Plugin) Routes() osquery.ExtensionPluginResponse {
	routes := []map[string]string{}
	for _, col := range t.columns {
		routes = append(routes, map[string]string{
			"id":   "column",
			"name": col.Name,
			"type": string(col.Type),
			"op":   "0",
		})
	}
	return routes
}

func (t *Plugin) Call(ctx context.Context, request osquery.ExtensionPluginRequest) osquery.ExtensionResponse {
	ctx, span := traces.StartSpan(ctx, t.name, "action", request["action"], "table_name", t.name)
	defer span.End()

	ok := osquery.ExtensionStatus{Code: 0, Message: "OK"}
	switch request["action"] {
	case "generate":
		queryContext, err := parseQueryContext(request["context"])
		if err != nil {
			return osquery.ExtensionResponse{
				Status: &osquery.ExtensionStatus{
					Code:    1,
					Message: "error parsing context JSON: " + err.Error(),
				},
			}
		}

		rows, err := t.generate(ctx, *queryContext)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return osquery.ExtensionResponse{
				Status: &osquery.ExtensionStatus{
					Code:    1,
					Message: "error generating table: " + err.Error(),
				},
			}
		}

		return osquery.ExtensionResponse{
			Status:   &ok,
			Response: rows,
		}

	case "columns":
		return osquery.ExtensionResponse{
			Status:   &ok,
			Response: t.Routes(),
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

func (t *Plugin) Ping() osquery.ExtensionStatus {
	return osquery.ExtensionStatus{Code: 0, Message: "OK"}
}

func (t *Plugin) Shutdown() {}

// ColumnDefinition defines the relevant information for a column in a table
// plugin. Both values are mandatory. Prefer using the *Column helpers to
// create ColumnDefinition structs.
type ColumnDefinition struct {
	Name string
	Type ColumnType
}

// TextColumn is a helper for defining columns containing strings.
func TextColumn(name string) ColumnDefinition {
	return ColumnDefinition{
		Name: name,
		Type: ColumnTypeText,
	}
}

// IntegerColumn is a helper for defining columns containing integers.
func IntegerColumn(name string) ColumnDefinition {
	return ColumnDefinition{
		Name: name,
		Type: ColumnTypeInteger,
	}
}

// BigIntColumn is a helper for defining columns containing big integers.
func BigIntColumn(name string) ColumnDefinition {
	return ColumnDefinition{
		Name: name,
		Type: ColumnTypeBigInt,
	}
}

// DoubleColumn is a helper for defining columns containing floating point
// values.
func DoubleColumn(name string) ColumnDefinition {
	return ColumnDefinition{
		Name: name,
		Type: ColumnTypeDouble,
	}
}

// ColumnType is a strongly typed representation of the data type string for a
// column definition. The named constants should be used.
type ColumnType string

// The following column types are defined in osquery tables.h.
const (
	ColumnTypeText    ColumnType = "TEXT"
	ColumnTypeInteger            = "INTEGER"
	ColumnTypeBigInt             = "BIGINT"
	ColumnTypeDouble             = "DOUBLE"
)

// QueryContext contains the constraints from the WHERE clause of the query,
// that can optionally be used to optimize the table generation. Note that the
// osquery SQLite engine will perform the filtering with these constraints, so
// it is not mandatory that they be used in table generation.
type QueryContext struct {
	// Constraints is a map from column name to the details of the
	// constraints on that column.
	Constraints map[string]ConstraintList
}

// ConstraintList contains the details of the constraints for the given column.
type ConstraintList struct {
	Affinity    ColumnType
	Constraints []Constraint
}

// Constraint contains both an operator and an expression that are applied as
// constraints in the query.
type Constraint struct {
	Operator   Operator
	Expression string
}

// Operator is an enum of the osquery operators.
type Operator int

// The following operators are dfined in osquery tables.h.
const (
	OperatorEquals              Operator = 2
	OperatorGreaterThan                  = 4
	OperatorLessThanOrEquals             = 8
	OperatorLessThan                     = 16
	OperatorGreaterThanOrEquals          = 32
	OperatorMatch                        = 64
	OperatorLike                         = 65
	OperatorGlob                         = 66
	OperatorRegexp                       = 67
	OperatorUnique                       = 1
)

// The following types and functions exist for parsing of the queryContext
// JSON and are not made public.
type queryContextJSON struct {
	Constraints []constraintListJSON `json:"constraints"`
}

type constraintListJSON struct {
	Name     string          `json:"name"`
	Affinity string          `json:"affinity"`
	List     json.RawMessage `json:"list"`
}

func parseQueryContext(ctxJSON string) (*QueryContext, error) {
	var parsed queryContextJSON

	err := json.Unmarshal([]byte(ctxJSON), &parsed)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshaling context JSON")
	}

	ctx := QueryContext{map[string]ConstraintList{}}
	for _, cList := range parsed.Constraints {
		constraints, err := parseConstraintList(cList.List)
		if err != nil {
			return nil, err
		}

		ctx.Constraints[cList.Name] = ConstraintList{
			Affinity:    ColumnType(cList.Affinity),
			Constraints: constraints,
		}
	}

	return &ctx, nil
}

func parseConstraintList(constraints json.RawMessage) ([]Constraint, error) {
	var str string
	err := json.Unmarshal(constraints, &str)
	if err == nil {
		// string indicates empty list
		return []Constraint{}, nil
	}

	var cList []map[string]interface{}
	err = json.Unmarshal(constraints, &cList)
	if err != nil {
		// cannot do anything with other types
		return nil, errors.Errorf("unexpected context list: %s", string(constraints))
	}

	cl := []Constraint{}
	for _, c := range cList {
		var op Operator
		switch opVal := c["op"].(type) {
		case string: // osquery < 3.0 with stringy types
			opInt, err := strconv.Atoi(opVal)
			if err != nil {
				return nil, errors.Errorf("parsing operator int: %s", c["op"])
			}
			op = Operator(opInt)
		case float64: // osquery > 3.0 with strong types
			op = Operator(opVal)
		default:
			return nil, errors.Errorf("cannot parse type %T", opVal)
		}

		expr, ok := c["expr"].(string)
		if !ok {
			return nil, errors.Errorf("expr should be string: %s", c["expr"])
		}

		cl = append(cl, Constraint{
			Operator:   op,
			Expression: expr,
		})
	}
	return cl, nil
}
