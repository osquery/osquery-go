package traces

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	instrumentationPkg = "github.com/osquery/osquery-go"
	osqueryGoVersion   = "0.0.0"
)

// By default, use the global tracer provider
var tracerProvider = otel.GetTracerProvider()

// SetTracerProvider allows consuming libraries to set a custom/non-global tracer provider.
func SetTracerProvider(tp trace.TracerProvider) {
	tracerProvider = tp
}

// OsqueryGoTracer provides a tracer with a standardized name and version.
// It should be used to start a span that requires `SpanStartOption`s that are
// not supported by `StartSpan` below -- i.e., any `SpanStartOption` besides
// `WithAttributes`.
func OsqueryGoTracer() trace.Tracer {
	return tracerProvider.Tracer(instrumentationPkg, trace.WithInstrumentationVersion(osqueryGoVersion))
}

// StartSpan is a wrapper around trace.Tracer.Start that simplifies passing in span attributes.
// `keyVals` should be a list of pairs, where the first in the pair is a string representing
// the attribute key and the second in the pair is the attribute value.
// The caller is always responsible for ending the returned span.
// Any spans requiring more specific configuration can be created manually via OsqueryGoTracer().Start.
func StartSpan(ctx context.Context, spanName string, keyVals ...string) (context.Context, trace.Span) {
	attrs := make([]attribute.KeyValue, 0)

	for i := 0; i < len(keyVals); i += 2 {
		// Ensure all attributes are appropriately namespaced
		key := fmt.Sprintf("osquery-go.%s", keyVals[i])
		attrs = append(attrs, attribute.String(key, keyVals[i+1]))
	}

	opts := []trace.SpanStartOption{trace.WithAttributes(attrs...)}

	return OsqueryGoTracer().Start(ctx, spanName, opts...)
}
