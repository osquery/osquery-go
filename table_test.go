package osquery

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseConstraintList(t *testing.T) {
	var testCases = []struct {
		json        string
		constraints []Constraint
		shouldErr   bool
	}{
		{
			json:      "bad",
			shouldErr: true,
		},
		{
			json:      `{"foo": "bar"}`,
			shouldErr: true,
		},
		{
			json:        `""`,
			constraints: []Constraint{},
		},
		{
			json: `[{"op":"2","expr":"foo"}]`,
			constraints: []Constraint{
				Constraint{OperatorEquals, "foo"},
			},
		},
		{
			json: `[{"op":"4","expr":"3"},{"op":"16","expr":"4"}]`,
			constraints: []Constraint{
				Constraint{OperatorGreaterThan, "3"},
				Constraint{OperatorLessThan, "4"},
			},
		},
	}

	for _, tt := range testCases {
		t.Run("", func(t *testing.T) {
			constraints, err := parseConstraintList(json.RawMessage(tt.json))
			if tt.shouldErr {
				assert.NotNil(t, err)
			} else {
				assert.Equal(t, tt.constraints, constraints)
			}
		})
	}
}

func TestParseQueryContext(t *testing.T) {
	var testCases = []struct {
		json      string
		context   QueryContext
		shouldErr bool
	}{
		{
			json:      "",
			shouldErr: true,
		},
		{
			json: `
{
  "constraints":[
    {
      "name":"big_int",
      "list":"",
      "affinity":"BIGINT"
    },
    {
      "name":"double",
      "list":"",
      "affinity":"DOUBLE"
    },
    {
      "name":"integer",
      "list":"",
      "affinity":"INTEGER"
    },
    {
      "name":"text",
      "list":[
        {
          "op":"2",
          "expr":"foo"
        }
      ],
      "affinity":"TEXT"
    }
  ]
}`,
			context: QueryContext{map[string]ConstraintList{
				"big_int": ConstraintList{ColumnTypeBigInt, []Constraint{}},
				"double":  ConstraintList{ColumnTypeDouble, []Constraint{}},
				"integer": ConstraintList{ColumnTypeInteger, []Constraint{}},
				"text":    ConstraintList{ColumnTypeText, []Constraint{{OperatorEquals, "foo"}}},
			}},
		},
		{
			json: `
{
  "constraints":[
    {
      "name":"big_int",
      "list":"",
      "affinity":"BIGINT"
    },
    {
      "name":"double",
      "list":[
        {
          "op":"32",
          "expr":"3.1"
        }
      ],
      "affinity":"DOUBLE"
    },
    {
      "name":"integer",
      "list":"",
      "affinity":"INTEGER"
    },
    {
      "name":"text",
      "list":[
        {
          "op":"2",
          "expr":"foobar"
        }
      ],
      "affinity":"TEXT"
    }
  ]
}
`,
			context: QueryContext{map[string]ConstraintList{
				"big_int": ConstraintList{ColumnTypeBigInt, []Constraint{}},
				"double":  ConstraintList{ColumnTypeDouble, []Constraint{{OperatorGreaterThanOrEquals, "3.1"}}},
				"integer": ConstraintList{ColumnTypeInteger, []Constraint{}},
				"text":    ConstraintList{ColumnTypeText, []Constraint{{OperatorEquals, "foobar"}}},
			}},
		},
	}
	for _, tt := range testCases {
		t.Run("", func(t *testing.T) {
			context, err := parseQueryContext(tt.json)
			if tt.shouldErr {
				assert.NotNil(t, err)
			} else {
				assert.Equal(t, &tt.context, context)
			}
		})
	}
}
