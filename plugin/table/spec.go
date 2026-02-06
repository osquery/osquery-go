package table

import (
	"encoding/json"

	"github.com/pkg/errors"
)

type osqueryTableSpec struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Url         string             `json:"url"`
	Platforms   []string           `json:"platforms"`
	Evented     bool               `json:"evented"`
	Cacheable   bool               `json:"cacheable"`
	Notes       string             `json:"notes",omitempty`
	Examples    []string           `json:"examples",omitempty`
	Columns     []ColumnDefinition `json:"columns"`
}

func (t *Plugin) Spec() ([]byte, error) {
	// FIXME: the columndefinition type is upcased, is that an issue?
	tableSpec := osqueryTableSpec{
		Name:        t.name,
		Description: t.description,
		Url:         t.url,
		Platforms:   []string{"blar"},
		Notes:       t.notes,
		Examples:    t.examples,
		Columns:     t.columns,
	}
	specBytes, err := json.MarshalIndent(tableSpec, "", "  ")
	if err != nil {
		return nil, errors.Wrap(err, "marshalling")
	}
	return specBytes, nil
}
