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
	insert   InsertFuncImpl
	update   UpdateFuncImpl
}

type RowDefinition interface{}

type RowID int

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

		fieldTag, fieldTagExists := field.Tag.Lookup("column")

		if field.Type == reflect.TypeOf(RowID(0)) && !fieldTagExists {
			continue
		}

		columnName := field.Name
		if fieldTagExists {
			columnName = strings.Split(fieldTag, ",")[0]
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
			fieldTag, fieldTagExists := field.Tag.Lookup("column")
			if fieldTagExists {
				columnName = strings.Split(fieldTag, ",")[0]
			}
			if field.Type == reflect.TypeOf(RowID(0)) && !fieldTagExists {
				columnName = "rowid" // magic string that makes osquery pass this value back as the identifier for "update" calls
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

func (t *Plugin) Call(ctx context.Context, request osquery.ExtensionPluginRequest) (response osquery.ExtensionResponse) {
	fmt.Println("Got request", request)
	defer func() {
		fmt.Println("Returning response", response)
		fmt.Println()
	}()
	ok := osquery.ExtensionStatus{Code: 0, Message: "OK"}
	switch request["action"] {
	case "generate":
		resp, err := t.generateRows(ctx, request)
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

	case "insert":
		resp, err := t.insertRow(ctx, request)
		if err != nil {
			return osquery.ExtensionResponse{
				Status: &osquery.ExtensionStatus{
					Code:    1,
					Message: err.Error(),
				},
				Response: osquery.ExtensionPluginResponse{
					map[string]string{
						"status":  "failure", // TODO: support the special "readonly" and "constraint" errors here
						"message": err.Error(),
					},
				},
			}
		}
		return osquery.ExtensionResponse{
			Status:   &osquery.ExtensionStatus{Code: 0, Message: "OK"},
			Response: resp,
		}

	case "update":
		resp, err := t.updateRow(ctx, request)
		if err != nil {
			return osquery.ExtensionResponse{
				Status: &osquery.ExtensionStatus{
					Code:    1,
					Message: err.Error(),
				},
				Response: osquery.ExtensionPluginResponse{
					map[string]string{
						"status":  "failure", // TODO: support the special "readonly" and "constraint" errors here
						"message": err.Error(),
					},
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

func (t *Plugin) generateRows(ctx context.Context, request osquery.ExtensionPluginRequest) (osquery.ExtensionPluginResponse, error) {
	if t.generate == nil {
		return nil, fmt.Errorf("unsupported operation \"generate\"")
	}
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

func (t *Plugin) insertRow(ctx context.Context, request osquery.ExtensionPluginRequest) (osquery.ExtensionPluginResponse, error) {
	if t.insert == nil {
		return nil, fmt.Errorf("unsupported operation \"insert\"")
	}
	row, err := parseRowValues(request["json_value_array"], t.rowType)
	if err != nil {
		return nil, err
	}

	rowID, err := t.insert(ctx, row)
	if err != nil {
		return nil, fmt.Errorf("error inserting row: %w", err)
	}

	return []map[string]string{
		{
			"id":     fmt.Sprint(rowID),
			"status": "success",
		},
	}, nil
}

func (t *Plugin) updateRow(ctx context.Context, request osquery.ExtensionPluginRequest) (osquery.ExtensionPluginResponse, error) {
	if t.update == nil {
		return nil, fmt.Errorf("unsupported operation \"update\"")
	}
	row, err := parseRowValues(request["json_value_array"], t.rowType)
	if err != nil {
		return nil, err
	}

	rowID, err := strconv.Atoi(request["id"])
	if err != nil {
		return nil, err
	}

	err = t.update(ctx, rowID, row)
	if err != nil {
		return nil, fmt.Errorf("error updating row: %w", err)
	}

	return []map[string]string{
		{
			"status": "success",
		},
	}, nil
}

func parseRowValues(rowJSON string, definition RowDefinition) (RowDefinition, error) {
	fmt.Println("Parsing rowJSON", rowJSON)
	var rowValues []json.RawMessage
	if err := json.Unmarshal([]byte(rowJSON), &rowValues); err != nil {
		return nil, err
	}

	row := reflect.New(reflect.TypeOf(definition)).Elem()
	offset := 0
	for i := 0; i < row.Type().NumField(); i++ {
		field := row.Type().Field(i)

		_, fieldTagExists := field.Tag.Lookup("column")
		if field.Type == reflect.TypeOf(RowID(0)) && !fieldTagExists {
			// This is just a row ID field that isn't an actual column
			offset--
			continue
		}

		rowValue := rowValues[i+offset]
		switch field.Type.Kind() {
		case reflect.String:
			row.Field(i).SetString(string(rowValue))

		case reflect.Int:
			intValue, err := strconv.Atoi(string(rowValue))
			if err != nil {
				return nil, err
			}
			row.Field(i).SetInt(int64(intValue))

		case reflect.Float64:
			floatValue, err := strconv.ParseFloat(string(rowValue), 64)
			if err != nil {
				return nil, err
			}
			row.Field(i).SetFloat(floatValue)

		default:
			if field.Type == reflect.TypeOf(&big.Int{}) {
				bigIntValue, ok := big.NewInt(0).SetString(string(rowValue), 10)
				if !ok {
					return nil, fmt.Errorf("invalid big.Int %s", string(rowValue))
				}
				row.Field(i).Set(reflect.ValueOf(bigIntValue))
				break
			}
			return nil, fmt.Errorf("field %s has unsupported type %s", field.Name, field.Type.Kind())
		}
	}

	return row.Interface(), nil
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
