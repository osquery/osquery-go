// Package table creates an osquery table plugin.
package table

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	"github.com/kolide/osquery-go/gen/osquery"
	"github.com/pkg/errors"
)

type Plugin struct {
	name     string
	rowType  RowDefinition
	columns  []ColumnDefinition
	generate GenerateFuncImpl
}

type RowDefinition interface{}

type Option func(*Plugin)

func NewPlugin(name string, rowDefinition RowDefinition, options ...Option) (*Plugin, error) {
	columns, err := generateColumnDefinition(rowDefinition)
	if err != nil {
		return nil, err
	}

	plugin := &Plugin{
		name:    name,
		rowType: rowDefinition,
		columns: columns,
	}

	for _, option := range options {
		option(plugin)
	}

	return plugin, nil
}

func generateColumnDefinition(rowDefinition RowDefinition) ([]ColumnDefinition, error) {
	row := reflect.ValueOf(rowDefinition)
	if row.Kind() != reflect.Struct {
		return nil, fmt.Errorf("row definition must be a struct")
	}

	var columns []ColumnDefinition
	for i := 0; i < row.Type().NumField(); i++ {
		field := row.Type().Field(i)

		columnName := field.Name
		if tag, ok := field.Tag.Lookup("column"); ok {
			columnName = strings.Split(tag, ",")[0]
		}

		var columnType ColumnType
		switch field.Type.Kind() {
		case reflect.String:
			columnType = ColumnTypeText
		case reflect.Int:
			columnType = ColumnTypeInteger
		case reflect.Float64:
			columnType = ColumnTypeDouble
		default:
			if field.Type == reflect.TypeOf(&big.Int{}) {
				columnType = ColumnTypeBigInt
				break
			}
			return nil, fmt.Errorf("field %s has unsupported type %s", field.Name, field.Type.Kind())
		}

		columns = append(columns, ColumnDefinition{
			Name: columnName,
			Type: columnType,
		})
	}
	return columns, nil
}

func rowsToPluginResponse(rows ...RowDefinition) osquery.ExtensionPluginResponse {
	var response osquery.ExtensionPluginResponse

	for _, rowDefinition := range rows {
		row := reflect.ValueOf(rowDefinition)
		result := map[string]string{}
		for i := 0; i < row.Type().NumField(); i++ {
			field := row.Type().Field(i)

			columnName := field.Name
			if tag, ok := field.Tag.Lookup("column"); ok {
				columnName = strings.Split(tag, ",")[0]
			}

			result[columnName] = fmt.Sprint(row.Field(i).Interface())
		}
		response = append(response, result)
	}
	return response
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
	ok := osquery.ExtensionStatus{Code: 0, Message: "OK"}
	switch request["action"] {
	case "generate":
		resp, err := t.generateCall(ctx, request)
		if err != nil {
			return osquery.ExtensionResponse{
				Status: &osquery.ExtensionStatus{
					Code:    1,
					Message: err.Error(),
				},
			}
		}
		return osquery.ExtensionResponse{
			Status:   &osquery.ExtensionStatus{Code: 0, Message: "OK"},
			Response: resp,
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

func (t *Plugin) generateCall(ctx context.Context, request osquery.ExtensionPluginRequest) (osquery.ExtensionPluginResponse, error) {
	queryContext, err := parseQueryContext(request["context"])
	if err != nil {
		return nil, fmt.Errorf("error parsing context JSON: %w", err)
	}

	rows, err := t.generate(ctx, *queryContext)
	if err != nil {
		return nil, fmt.Errorf("error generating table: %w", err)
	}

	return rowsToPluginResponse(rows...), nil
}

// ColumnDefinition defines the relevant information for a column in a table
// plugin. Both values are mandatory. Prefer using the *Column helpers to
// create ColumnDefinition structs.
type ColumnDefinition struct {
	Name string
	Type ColumnType
}

// ColumnType is a strongly typed representation of the data type string for a
// column definition. The named constants should be used.
type ColumnType string

// The following column types are defined in osquery tables.h.
const (
	ColumnTypeText    ColumnType = "TEXT"
	ColumnTypeInteger ColumnType = "INTEGER"
	ColumnTypeBigInt  ColumnType = "BIGINT"
	ColumnTypeDouble  ColumnType = "DOUBLE"
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
	OperatorGreaterThan         Operator = 4
	OperatorLessThanOrEquals    Operator = 8
	OperatorLessThan            Operator = 16
	OperatorGreaterThanOrEquals Operator = 32
	OperatorMatch               Operator = 64
	OperatorLike                Operator = 65
	OperatorGlob                Operator = 66
	OperatorRegexp              Operator = 67
	OperatorUnique              Operator = 1
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
