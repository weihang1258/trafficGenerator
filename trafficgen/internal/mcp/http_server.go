package mcp

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trafficgen/trafficgen/internal/api/rest"
	"go.uber.org/zap"
)

// HTTPServer wraps an *http.Server that serves the MCP Streamable HTTP
// transport. It enforces API key authentication via the X-MCP-Key header,
// applies CORS restrictions, and binds to a configurable listen address.
//
// Security model:
//   - API key is mandatory. If mcp.api_key is empty, NewHTTPServer returns
//     an error -- we refuse to expose an unauthenticated remote endpoint.
//   - API key comparison uses crypto/subtle.ConstantTimeCompare to prevent
//     timing attacks.
//   - CORS defaults to localhost only; production deployments must explicitly
//     widen cors_origins.
//   - Session timeout (30 min idle) prevents session goroutine leaks from
//     disconnected clients.
//   - DNS rebinding protection stays enabled (SDK default) to prevent
//     localhost-bound servers being accessed via public hostnames.
type HTTPServer struct {
	srv     *http.Server
	handler *mcp.StreamableHTTPHandler
}

// NewHTTPServer constructs the HTTP transport handler. The server is not
// started; call Start with a context to begin serving.
//
// Returns an error if api_key is empty (refusing unauthenticated remote
// access) or if listen is empty.
func NewHTTPServer(s *Server, listen string, apiKey string, corsOrigins []string) (*HTTPServer, error) {
	if listen == "" {
		return nil, errors.New("mcp.http.listen is empty; configure a bind address (e.g. 127.0.0.1:8081)")
	}
	if apiKey == "" {
		return nil, errors.New("mcp.api_key is empty; refusing to start HTTP transport without authentication " +
			"(remote MCP requires an API key to prevent unauthorized access)")
	}

	streamHandler := mcp.NewStreamableHTTPHandler(
		func(req *http.Request) *mcp.Server {
			return s.MCP()
		},
		&mcp.StreamableHTTPOptions{
			SessionTimeout: 30 * time.Minute,
		},
	)

	mux := http.NewServeMux()
	// Middleware order: CORS OUTSIDE API key. This is critical because browser
	// CORS preflight (OPTIONS) requests do NOT include custom headers like
	// X-MCP-Key (the spec forbids it). If API key were outermost, every
	// preflight would 401 and browsers would block all cross-origin requests.
	// With CORS outermost: preflight gets 204 + CORS headers; actual POST/GET
	// still goes through apiKeyMiddleware which enforces X-MCP-Key.
	// Tag the request context with the request's own origin so tool handlers
	// can rewrite relative download links to absolute URLs (the origin the
	// client connected to is exactly what it can reach). Scheme: TLS state,
	// honoring X-Forwarded-Proto behind a reverse proxy. The go-sdk
	// propagates the HTTP request context into the tool handler.
	tagged := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if fp := r.Header.Get("X-Forwarded-Proto"); fp != "" {
			scheme = fp
		}
		base := scheme + "://" + r.Host
		streamHandler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), httpTransportKey{}, base)))
	})
	mux.Handle("/mcp", corsMiddleware(corsOrigins, apiKeyMiddleware(apiKey, tagged)))

	// Public pcap download links (no API key — the task UUID is the
	// capability token): mounted on the MCP port too, so an LLM client can
	// resolve a task's relative download_url against the host:port it is
	// already connected to (the REST port may not even be exposed).
	mux.Handle("/downloads/tasks/", corsMiddleware(corsOrigins, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest.ServeTaskPcapPublic(s.db, w, r)
	})))

	// Public pcap asset downloads (no API key — the asset UUID is the
	// capability token): imported assets and auto-registered task products
	// are fetchable through the MCP port too, so flowb_manage_pcaps
	// action=download's link works with the host:port the client already
	// uses.
	mux.Handle("/downloads/pcaps/", corsMiddleware(corsOrigins, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest.ServePcapPublic(s.db, w, r)
	})))

	// Pcap upload + registration in one step (multipart "file"): the write
	// counterpart of the download links above — same port, but keyed (X-MCP-Key
	// inside the CORS wrapper), since uploads must not be unauthenticated.
	mux.Handle("/uploads/pcaps", corsMiddleware(corsOrigins, apiKeyMiddleware(apiKey, http.HandlerFunc(s.uploadPcapHandler))))

	hs := &HTTPServer{
		srv: &http.Server{
			Addr:         listen,
			Handler:      mux,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 0, // streaming responses may be long-lived
			IdleTimeout:  120 * time.Second,
		},
		handler: streamHandler,
	}
	return hs, nil
}

// Start begins serving HTTP requests. Blocks until ctx is canceled or the
// server returns a fatal error. Caller should run this in a goroutine.
func (h *HTTPServer) Start(ctx context.Context) error {
	zap.L().Info("starting mcp http server",
		zap.String("listen", h.srv.Addr),
	)
	errCh := make(chan error, 1)
	go func() {
		if err := h.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := h.srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("http server shutdown: %w", err)
		}
		return nil
	}
}

// Shutdown gracefully stops the HTTP server, waiting up to 10s for in-flight
// requests to complete.
func (h *HTTPServer) Shutdown(ctx context.Context) error {
	return h.srv.Shutdown(ctx)
}

// apiKeyMiddleware rejects requests without a valid X-MCP-Key header.
// Comparison is constant-time to prevent timing attacks on the key.
func apiKeyMiddleware(apiKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := r.Header.Get("X-MCP-Key")
		if provided == "" {
			w.Header().Set("WWW-Authenticate", "X-MCP-Key")
			http.Error(w, "missing X-MCP-Key header", http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(apiKey)) != 1 {
			w.Header().Set("WWW-Authenticate", "X-MCP-Key")
			http.Error(w, "invalid API key", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware applies CORS headers based on the allowed origins list.
// An empty list denies all cross-origin requests. A "*" entry allows all
// origins (use only in dev). Origins may contain a trailing ":*" wildcard
// (e.g. "http://localhost:*") to match any port on that host -- this is the
// default config value and is expanded here, not by the caller.
type corsPattern struct {
	prefix string // e.g. "http://localhost:"
}

func corsMiddleware(allowedOrigins []string, next http.Handler) http.Handler {
	var patterns []corsPattern
	allowed := make(map[string]bool, len(allowedOrigins))
	allowAll := false
	for _, o := range allowedOrigins {
		if o == "*" {
			allowAll = true
			continue
		}
		// Normalize "scheme://host:*" to a prefix match so the default
		// "http://localhost:*" actually matches "http://localhost:3000".
		// Without this, the documented default would silently block every
		// browser dev server.
		if strings.HasSuffix(o, ":*") {
			patterns = append(patterns, corsPattern{prefix: o[:len(o)-1]}) // keep trailing ":"
			continue
		}
		allowed[o] = true
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && (allowAll || allowed[origin] || matchesPattern(patterns, origin)) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, X-MCP-Key, Mcp-Session-Id, Last-Event-ID")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE")
			// Expose Mcp-Session-Id so browser-based MCP clients can read it
			// from the initialize response (needed for subsequent requests).
			w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id")
			// Tell caches that the response varies on Origin so a cached
			// response for one origin is not served to a different origin.
			w.Header().Add("Vary", "Origin")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// matchesPattern returns true if origin starts with any pattern prefix.
func matchesPattern(patterns []corsPattern, origin string) bool {
	for _, p := range patterns {
		if strings.HasPrefix(origin, p.prefix) {
			return true
		}
	}
	return false
}
