package table

// OsqueryTableSpec is a struct compatible with the osquery spec files. It
// can be marshalled to json if desired.
type OsqueryTableSpec struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Url         string             `json:"url"`
	Platforms   []platformName     `json:"platforms"`
	Evented     bool               `json:"evented"`
	Cacheable   bool               `json:"cacheable"`
	Notes       string             `json:"notes,omitempty"`
	Examples    []string           `json:"examples,omitempty"`
	Columns     []ColumnDefinition `json:"columns"`
}

func (t *Plugin) Spec() OsqueryTableSpec {
	// FIXME: the columndefinition type is upcased, is that an issue?
	return OsqueryTableSpec{
		Name:        t.name,
		Description: t.description,
		Url:         t.url,
		Platforms:   t.platforms,
		Notes:       t.notes,
		Examples:    t.examples,
		Columns:     t.columns,
	}
}
