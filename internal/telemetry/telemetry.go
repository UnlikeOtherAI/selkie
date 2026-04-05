// Package telemetry initializes OpenTelemetry tracing and metrics exporters.
package telemetry

import (
	"context"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Config holds the settings required to connect to an OTLP collector.
type Config struct {
	Endpoint       string
	ServiceName    string
	ServiceVersion string
}

// Init sets up OpenTelemetry trace and metric providers. When cfg.Endpoint is
// empty, both providers fall back to no-op and the returned shutdown function
// is a no-op. The caller must invoke the returned shutdown function during
// graceful termination to flush pending telemetry.
func Init(ctx context.Context, cfg Config, logger *zap.Logger) (shutdown func(context.Context) error, err error) {
	if cfg.Endpoint == "" {
		logger.Info("OTEL endpoint not configured, telemetry disabled")
		return func(context.Context) error { return nil }, nil
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
		),
	)
	if err != nil {
		return nil, err
	}

	// Trace exporter.
	traceExp, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(cfg.Endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	// Metric exporter.
	metricExp, err := otlpmetricgrpc.New(ctx,
		otlpmetricgrpc.WithEndpoint(cfg.Endpoint),
		otlpmetricgrpc.WithInsecure(),
	)
	if err != nil {
		if tpErr := tp.Shutdown(ctx); tpErr != nil {
			return nil, tpErr
		}
		return nil, err
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp)),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(mp)

	logger.Info("OTEL telemetry initialized", zap.String("endpoint", cfg.Endpoint))

	shutdown = func(ctx context.Context) error {
		tpErr := tp.Shutdown(ctx)
		mpErr := mp.Shutdown(ctx)
		if tpErr != nil {
			return tpErr
		}
		return mpErr
	}
	return shutdown, nil
}

// Middleware returns an HTTP middleware that instruments every request with
// OpenTelemetry spans and metrics. When OTel has not been initialized (no
// endpoint configured), it returns a passthrough no-op middleware.
func Middleware(endpoint string) func(http.Handler) http.Handler {
	if endpoint == "" {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return otelhttp.NewHandler(next, "http.request",
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				return r.Method + " " + r.URL.Path
			}),
		)
	}
}

// SpanFromContext extracts the current OTel span from the given context.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}
