package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdkTrace "go.opentelemetry.io/otel/sdk/trace"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/buildinfo"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/metrics"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils"
)

// Server is the server based on Gin
type Server struct {
	appRouter *gin.Engine
	metrics   *metrics.TFAMetrics
	auth      auth.Provider

	// Servers
	appSrv     *http.Server
	metricsSrv *http.Server

	// Method that forces a reload of TLS certificates from disk
	tlsCertWatchFn tlsCertWatchFn

	// TLS configuration for the app server
	tlsConfig *tls.Config

	tracer  *sdkTrace.TracerProvider
	running atomic.Bool
	wg      sync.WaitGroup

	// Listeners for the app and metrics servers
	// These can be used for testing without having to start an actual TCP listener
	appListener     net.Listener
	metricsListener net.Listener

	// Optional function to add test routes
	// This is used in testing
	addTestRoutes func(s *Server)
}

// NewServerOpts contains options for the NewServer method
type NewServerOpts struct {
	Log           *slog.Logger
	Metrics       *metrics.TFAMetrics
	TraceExporter sdkTrace.SpanExporter
	Auth          auth.Provider

	// Optional function to add test routes
	// This is used in testing
	addTestRoutes func(s *Server)
}

// NewServer creates a new Server object and initializes it
func NewServer(opts NewServerOpts) (*Server, error) {
	s := &Server{
		auth:    opts.Auth,
		metrics: opts.Metrics,

		addTestRoutes: opts.addTestRoutes,
	}

	// Init the object
	err := s.init(opts.Log, opts.TraceExporter)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Init the Server object and create a Gin server
func (s *Server) init(log *slog.Logger, traceExporter sdkTrace.SpanExporter) (err error) {
	// Init tracer
	err = s.initTracer(traceExporter)
	if err != nil {
		return err
	}

	// Init the app server
	err = s.initAppServer(log)
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) initTracer(exporter sdkTrace.SpanExporter) error {
	cfg := config.Get()

	// If tracing is disabled, this is a no-op
	if exporter == nil {
		return nil
	}

	// Init the trace provider
	var sampler sdkTrace.Sampler
	switch {
	case cfg.TracingSampling == 1:
		sampler = sdkTrace.ParentBased(sdkTrace.AlwaysSample())
	case cfg.TracingSampling == 0:
		sampler = sdkTrace.NeverSample()
	case cfg.TracingSampling < 0, cfg.TracingSampling > 1:
		// Should never happen
		return errors.New("invalid tracing sampling: must be between 0 and 1")
	default:
		sampler = sdkTrace.ParentBased(sdkTrace.TraceIDRatioBased(cfg.TracingSampling))
	}

	s.tracer = sdkTrace.NewTracerProvider(
		sdkTrace.WithResource(cfg.GetOtelResource(buildinfo.AppName)),
		sdkTrace.WithSampler(sampler),
		sdkTrace.WithBatcher(exporter),
	)
	otel.SetTracerProvider(s.tracer)
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}),
	)

	return nil
}

func (s *Server) initAppServer(log *slog.Logger) (err error) {
	conf := config.Get()

	// Load the TLS configuration
	s.tlsConfig, s.tlsCertWatchFn, err = s.loadTLSConfig(log)
	if err != nil {
		return fmt.Errorf("failed to load TLS configuration: %w", err)
	}

	// Create the Gin router and add various middlewares
	s.appRouter = gin.New()
	s.appRouter.Use(gin.Recovery())
	if s.tracer != nil {
		s.appRouter.Use(otelgin.Middleware("appserver", otelgin.WithTracerProvider(s.tracer)))
	}
	s.appRouter.Use(s.MiddlewareRequestId)
	s.appRouter.Use(s.MiddlewareLogger(log))
	if s.metrics != nil {
		s.appRouter.Use(s.MiddlewareCountMetrics)
	}

	// Logger middleware that removes the auth code from the URL
	codeFilterLogMw := s.MiddlewareLoggerMask(regexp.MustCompile(`(\?|&)(code|state|session_state)=([^&]*)`), "$1$2***")

	// Healthz route
	// This does not follow BasePath
	s.appRouter.GET("/healthz", gin.WrapF(s.RouteHealthzHandler))

	// Auth routes
	// For the root route, we add it with and without trailing slash (in case BasePath isn't empty) to avoid Gin setting up a 301 (Permanent) redirect, which causes issues with forward auth
	appRoutes := s.appRouter.Group(conf.BasePath, s.MiddlewareProxyHeaders, s.MiddlewareWildcards)
	switch provider := s.auth.(type) {
	case auth.PlexProvider:
		appRoutes.GET("", s.MiddlewareRequireClientCertificate, s.MiddlewareLoadAuthCookie, s.PlexRoot(provider))
		if conf.BasePath != "" {
			appRoutes.GET("/", s.MiddlewareRequireClientCertificate, s.MiddlewareLoadAuthCookie, s.PlexCallback(provider))
		}
		appRoutes.GET("/oauth2/callback", codeFilterLogMw, s.PlexCallback(provider))
	case auth.OAuth2Provider:
		appRoutes.GET("", s.MiddlewareRequireClientCertificate, s.MiddlewareLoadAuthCookie, s.OAuthRoot(provider))
		if conf.BasePath != "" {
			appRoutes.GET("/", s.MiddlewareRequireClientCertificate, s.MiddlewareLoadAuthCookie, s.OAuthRoot(provider))
		}
		appRoutes.GET("/oauth2/callback", codeFilterLogMw, s.OAuthCallback(provider))
	case auth.SeamlessProvider:
		appRoutes.GET("", s.MiddlewareRequireClientCertificate, s.MiddlewareLoadAuthCookie, s.SeamlessRoot(provider))
		if conf.BasePath != "" {
			appRoutes.GET("/", s.MiddlewareRequireClientCertificate, s.MiddlewareLoadAuthCookie, s.SeamlessRoot(provider))
		}
	}
	appRoutes.GET("profile", s.MiddlewareLoadAuthCookie, s.RouteGetProfile)
	appRoutes.GET("logout", s.RouteGetLogout)

	// API Routes
	// These do not follow BasePath and do not require a client certificate, or loading the auth cookie, or the proxy headers
	apiRoutes := s.appRouter.Group("/api")
	apiRoutes.GET("/verify", s.RouteGetAPIVerify)

	// Test routes, that are enabled when running tests only
	if s.addTestRoutes != nil {
		s.addTestRoutes(s)
	}

	return nil
}

// Run the web server
// Note this function is blocking, and will return only when the servers are shut down via context cancellation.
func (s *Server) Run(ctx context.Context) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("server is already running")
	}
	defer s.running.Store(false)
	defer s.wg.Wait()

	cfg := config.Get()

	// App server
	s.wg.Add(1)
	err := s.startAppServer(ctx)
	if err != nil {
		return fmt.Errorf("failed to start app server: %w", err)
	}
	defer func() {
		// Handle graceful shutdown
		defer s.wg.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := s.appSrv.Shutdown(shutdownCtx)
		shutdownCancel()
		if err != nil {
			// Log the error only (could be context canceled)
			utils.LogFromContext(ctx).WarnContext(ctx,
				"App server shutdown error",
				slog.Any("error", err),
			)
		}
	}()

	// Metrics server
	if cfg.MetricsServerEnabled {
		s.wg.Add(1)
		err = s.startMetricsServer(ctx)
		if err != nil {
			return fmt.Errorf("failed to start metrics server: %w", err)
		}
		defer func() {
			// Handle graceful shutdown
			defer s.wg.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			err := s.metricsSrv.Shutdown(shutdownCtx)
			shutdownCancel()
			if err != nil {
				// Log the error only (could be context canceled)
				utils.LogFromContext(ctx).WarnContext(ctx,
					"Metrics server shutdown error",
					slog.Any("error", err),
				)
			}
		}()
	}

	// If we have a tlsCertWatchFn, invoke that
	if s.tlsCertWatchFn != nil {
		err = s.tlsCertWatchFn(ctx)
		if err != nil {
			return fmt.Errorf("failed to watch for TLS certificates: %w", err)
		}
	}

	// Block until the context is canceled
	<-ctx.Done()

	// Servers are stopped with deferred calls
	return nil
}

func (s *Server) startAppServer(ctx context.Context) error {
	cfg := config.Get()
	log := utils.LogFromContext(ctx)

	// Create the HTTP(S) server
	s.appSrv = &http.Server{
		Addr:              net.JoinHostPort(cfg.Bind, strconv.Itoa(cfg.Port)),
		MaxHeaderBytes:    1 << 20,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if s.tlsConfig != nil {
		// Using TLS
		s.appSrv.Handler = s.appRouter
		s.appSrv.TLSConfig = s.tlsConfig
	} else {
		// Not using TLS
		// Here we also need to enable HTTP/2 Cleartext
		h2s := &http2.Server{}
		s.appSrv.Handler = h2c.NewHandler(s.appRouter, h2s)
	}

	// Create the listener if we don't have one already
	if s.appListener == nil {
		var err error
		s.appListener, err = net.Listen("tcp", s.appSrv.Addr)
		if err != nil {
			return fmt.Errorf("failed to create TCP listener: %w", err)
		}
	}

	// Start the HTTP(S) server in a background goroutine
	log.InfoContext(ctx, "App server started",
		slog.String("bind", cfg.Bind),
		slog.Int("port", cfg.Port),
		slog.Bool("tls", s.tlsConfig != nil),
	)
	go func() {
		defer s.appListener.Close()

		// Next call blocks until the server is shut down
		var srvErr error
		if s.tlsConfig != nil {
			srvErr = s.appSrv.ServeTLS(s.appListener, "", "")
		} else {
			srvErr = s.appSrv.Serve(s.appListener)
		}
		if srvErr != http.ErrServerClosed {
			utils.FatalError(log, "Error starting app server", srvErr)
		}
	}()

	return nil
}

func (s *Server) startMetricsServer(ctx context.Context) error {
	cfg := config.Get()
	log := utils.LogFromContext(ctx)

	// Handler
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.RouteHealthzHandler)
	mux.Handle("/metrics", s.metrics.HTTPHandler())

	// Create the HTTP server
	s.metricsSrv = &http.Server{
		Addr:              net.JoinHostPort(cfg.MetricsServerBind, strconv.Itoa(cfg.MetricsServerPort)),
		Handler:           mux,
		MaxHeaderBytes:    1 << 20,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Create the listener if we don't have one already
	if s.metricsListener == nil {
		var err error
		s.metricsListener, err = net.Listen("tcp", s.metricsSrv.Addr)
		if err != nil {
			return fmt.Errorf("failed to create TCP listener: %w", err)
		}
	}

	// Start the HTTPS server in a background goroutine
	log.InfoContext(ctx, "Metrics server started",
		slog.String("bind", cfg.MetricsServerBind),
		slog.Int("port", cfg.MetricsServerPort),
	)
	go func() {
		defer s.metricsListener.Close()

		// Next call blocks until the server is shut down
		srvErr := s.metricsSrv.Serve(s.metricsListener)
		if srvErr != http.ErrServerClosed {
			utils.FatalError(log, "Error starting metrics server", srvErr)
		}
	}()

	return nil
}

// Loads the TLS configuration
func (s *Server) loadTLSConfig(log *slog.Logger) (tlsConfig *tls.Config, watchFn tlsCertWatchFn, err error) {
	cfg := config.Get()

	tlsConfig = &tls.Config{
		MinVersion: minTLSVersion,
	}

	// If "tlsPath" is empty, use the folder where the config file is located
	tlsPath := cfg.TLSPath
	if tlsPath == "" {
		file := cfg.GetLoadedConfigPath()
		if file != "" {
			tlsPath = filepath.Dir(file)
		}
	}

	// Start by setting the CA certificate and enable mTLS if required
	if cfg.TLSClientAuth {
		// Check if we have the actual keys
		caCert := []byte(cfg.TLSCAPEM)

		// If caCert is empty, we need to load the CA certificate from file
		if len(caCert) > 0 {
			log.Debug("Loaded CA certificate from PEM value")
		} else {
			if tlsPath == "" {
				return nil, nil, errors.New("cannot find a CA certificate, which is required when `tlsClientAuth` is enabled: no path specified in option `tlsPath`, and no config file was loaded")
			}

			caCert, err = os.ReadFile(filepath.Join(tlsPath, tlsCAFile))
			if err != nil {
				// This also returns an error if the file doesn't exist
				// We want to error here as `tlsClientAuth` is true
				return nil, nil, fmt.Errorf("failed to load CA certificate file from path '%s' and 'tlsClientAuth' option is enabled: %w", tlsPath, err)
			}

			log.Debug("Loaded CA certificate from disk", "path", tlsPath)
		}

		caCertPool := x509.NewCertPool()
		ok := caCertPool.AppendCertsFromPEM(caCert)
		if !ok {
			return nil, nil, fmt.Errorf("failed to import CA certificate from PEM found at path '%s'", tlsPath)
		}

		// Set ClientAuth to VerifyClientCertIfGiven because not all endpoints we have require mTLS
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		tlsConfig.ClientCAs = caCertPool

		log.Debug("TLS Client Authentication is enabled for sensitive endpoints")
	}

	// Let's set the server cert and key now
	// First, check if we have actual keys
	tlsCert := cfg.TLSCertPEM
	tlsKey := cfg.TLSKeyPEM

	// If we don't have actual keys, then we need to load from file and reload when the files change
	if tlsCert == "" && tlsKey == "" {
		if tlsPath == "" {
			// No config file loaded, so don't attempt to load TLS certs
			return nil, nil, nil
		}

		var provider *tlsCertProvider
		provider, err = newTLSCertProvider(tlsPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load TLS certificates from path '%s': %w", tlsPath, err)
		}

		// If newTLSCertProvider returns nil, there are no TLS certificates, so disable TLS
		if provider == nil {
			return nil, nil, nil
		}

		log.Debug("Loaded TLS certificates from disk", "path", tlsPath)

		tlsConfig.GetCertificate = provider.GetCertificateFn()

		return tlsConfig, provider.Watch, nil
	}

	// Assume the values from the config file are PEM-encoded certs and key
	if tlsCert == "" || tlsKey == "" {
		// If tlsCert and/or tlsKey is empty, do not use TLS
		return nil, nil, nil
	}

	cert, err := tls.X509KeyPair([]byte(tlsCert), []byte(tlsKey))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse TLS certificate or key: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	log.Debug("Loaded TLS certificates from PEM values")

	return tlsConfig, nil, nil
}
