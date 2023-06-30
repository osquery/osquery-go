package traces

import (
	"context"
	"fmt"
	"runtime"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	instrumentationPkg = "github.com/osquery/osquery-go"
	osqueryGoVersion   = "0.0.0"
)

// OsqueryGoTracer provides a tracer with a standardized name and version.
func OsqueryGoTracer() trace.Tracer {
	return otel.Tracer(instrumentationPkg, trace.WithInstrumentationVersion(osqueryGoVersion))
}

// StartSpan is a wrapper around trace.Tracer.Start that simplifies passing in span attributes.
// `keyVals` should be a list of pairs, where the first in the pair is a string representing
// the attribute key and the second in the pair is the attribute value.
// The caller is always responsible for ending the returned span.
// Any spans requiring more specific configuration can be created manually via OsqueryGoTracer().Start.
func StartSpan(ctx context.Context, spanName string, keyVals ...interface{}) (context.Context, trace.Span) {
	opts := make([]trace.SpanStartOption, 0)

	// Extract information about the caller to set some standard attributes (code.filepath,
	// code.lineno, code.function) and to set more specific span and attribute names.
	// runtime.Caller(0) would return information about `StartSpan` -- calling
	// runtime.Caller(1) will return information about the function calling `StartSpan`.
	programCounter, callerFile, callerLine, ok := runtime.Caller(1)
	if ok {
		opts = append(opts, trace.WithAttributes(
			semconv.CodeFilepath(callerFile),
			semconv.CodeLineNumber(callerLine),
		))

		// Extract the calling function name and use it to set code.function.
		if f := runtime.FuncForPC(programCounter); f != nil {
			opts = append(opts, trace.WithAttributes(semconv.CodeFunction(f.Name())))
		}
	}

	opts = append(opts, trace.WithAttributes(buildAttributes(keyVals...)...))

	return otel.Tracer(instrumentationPkg, trace.WithInstrumentationVersion(osqueryGoVersion)).Start(ctx, spanName, opts...)
}

// buildAttributes takes the given keyVals, expected to be pairs representing the key
// and value of each attribute, and parses them appropriately, ensuring that the keys
// have consistent and specific names. Pairs with invalid keys or values will be added
// as string attributes.
func buildAttributes(keyVals ...interface{}) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0)

	for i := 0; i < len(keyVals); i += 2 {
		// Keys must always be strings
		if _, ok := keyVals[i].(string); !ok {
			attrs = append(attrs, attribute.String(
				fmt.Sprintf("bad key type %T: %v", keyVals[i], keyVals[i]),
				fmt.Sprintf("%v", keyVals[i+1]),
			))
			continue
		}

		key := fmt.Sprintf("osquery-go.%s", keyVals[i])

		// Create an attribute of the appropriate type
		switch v := keyVals[i+1].(type) {
		case bool:
			attrs = append(attrs, attribute.Bool(key, v))
		case []bool:
			attrs = append(attrs, attribute.BoolSlice(key, v))
		case int:
			attrs = append(attrs, attribute.Int(key, v))
		case []int:
			attrs = append(attrs, attribute.IntSlice(key, v))
		case int64:
			attrs = append(attrs, attribute.Int64(key, v))
		case []int64:
			attrs = append(attrs, attribute.Int64Slice(key, v))
		case float64:
			attrs = append(attrs, attribute.Float64(key, v))
		case []float64:
			attrs = append(attrs, attribute.Float64Slice(key, v))
		case string:
			attrs = append(attrs, attribute.String(key, v))
		case []string:
			attrs = append(attrs, attribute.StringSlice(key, v))
		default:
			attrs = append(attrs, attribute.String(key, fmt.Sprintf("unsupported value of type %T: %v", keyVals[i+1], keyVals[i+1])))
		}
	}

	return attrs
}
