package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// The UI is built from web/ into ui/dist (see ui/README.md). The directory
// always contains the README, so the binary builds without Node.
//
//go:embed all:ui
var uiFiles embed.FS

const uiNotBuilt = `<!doctype html><meta charset="utf-8"><title>Net Watcher</title>
<body style="font-family:system-ui;max-width:40rem;margin:4rem auto;line-height:1.5">
<h1>Net Watcher</h1><p>The API is running, but this binary was built without the web UI.</p>
<p>Build it with <code>make ui</code> (or <code>cd web &amp;&amp; npm ci &amp;&amp; npm run build</code>) and rebuild the binary.</p>`

// uiHandler serves the embedded build. Hashed assets are immutable; the
// entry document is revalidated so a new release is picked up immediately.
func uiHandler() http.Handler {
	dist, err := fs.Sub(uiFiles, "ui/dist")
	if err == nil {
		_, err = fs.Stat(dist, "index.html")
	}
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(uiNotBuilt))
		})
	}
	files := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

// securityHeaders replaces the former wildcard CORS policy. The UI is served
// from the same origin and loads nothing from third parties, so other sites
// must not be able to read audit data through a visitor's browser.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Cross-Origin-Opener-Policy", "same-origin")
		header.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}
