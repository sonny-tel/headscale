package hscontrol

import (
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/rs/zerolog/log"
)

// webuiHandler serves the SPA frontend.
// It serves static files from the configured static directory and
// falls back to index.html for any path that doesn't match a real
// file (client-side routing).
func (h *Headscale) webuiHandler() http.Handler {
	staticPath := h.cfg.WebUI.StaticPath
	basePath := strings.TrimRight(h.cfg.WebUI.BasePath, "/")

	var fileSystem http.FileSystem
	if staticPath != "" {
		fileSystem = http.Dir(staticPath)
	} else {
		// No static path configured — return 404 for everything.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "web UI static files not configured", http.StatusNotFound)
		})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip the base path prefix for file lookups.
		reqPath := r.URL.Path
		if basePath != "" {
			reqPath = strings.TrimPrefix(reqPath, basePath)
			if reqPath == "" {
				reqPath = "/"
			}
		}

		// Clean the path to prevent directory traversal.
		reqPath = path.Clean("/" + reqPath)

		// Try to open the requested file.
		f, err := fileSystem.Open(reqPath)
		if err != nil {
			if os.IsNotExist(err) {
				// SPA fallback — serve index.html for client-side routing.
				serveIndexHTML(w, r, fileSystem)

				return
			}

			log.Error().Err(err).Str("path", reqPath).Msg("error opening static file")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)

			return
		}
		defer f.Close()

		stat, err := f.Stat()
		if err != nil {
			log.Error().Err(err).Str("path", reqPath).Msg("error stating static file")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)

			return
		}

		// If directory, serve index.html.
		if stat.IsDir() {
			serveIndexHTML(w, r, fileSystem)

			return
		}

		// Serve the file directly using the resolved file handle.
		http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
	})
}

func serveIndexHTML(w http.ResponseWriter, r *http.Request, fileSystem http.FileSystem) {
	indexFile, err := fileSystem.Open("/index.html")
	if err != nil {
		http.Error(w, "index.html not found", http.StatusNotFound)

		return
	}
	defer indexFile.Close()

	stat, err := indexFile.Stat()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)

		return
	}

	// http.File implements io.ReadSeeker so this is safe.
	http.ServeContent(w, r, "index.html", stat.ModTime(), indexFile)
}
