package table

import "context"

type GenerateRowsImpl func(ctx context.Context, queryContext QueryContext) ([]RowDefinition, error)
type InsertRowImpl func(ctx context.Context, row RowDefinition) (rowID RowID, err error)
type UpdateRowImpl func(ctx context.Context, rowID RowID, row RowDefinition) error

// GenerateRows allows you to provide a function that is used by OSQuery
// to fulfill SELECT SQL statements.
//
// Your Generate function is passed a set of constraints (representing any WHERE clauses in the query).
// These are optional to do anything with: the OSQuery SQLite engine will do its own filtering but
// they can be useful as optimisations or for taking arguments.
func GenerateRows(generate GenerateRowsImpl) Option {
	return func(plugin *Plugin) {
		plugin.generate = generate
	}
}

// InsertRow allows you to provide a function that is used by OSQuery
// to fulfill INSERT SQL statements.
// Your Insert function must return a RowID.
func InsertRow(insert InsertRowImpl) Option {
	return func(plugin *Plugin) {
		plugin.insert = insert
	}
}

// UpdateRow allows you to provide a function that is used by OSQuery
// to fulfill UPDATE SQL statements.
// OSQuery first calls your GenerateRows function to find rows that should be updated
// and then calls UpdateRow once per row.
//
// If your provided RowDefinition has a field of type RowID then this is the value passed to your update function.
// If not, you are passed an index into the array returned from GenerateRows.
// It is *strongly* recommended to use a RowID
func UpdateRow(update UpdateRowImpl) Option {
	return func(plugin *Plugin) {
		plugin.update = update
	}
}
