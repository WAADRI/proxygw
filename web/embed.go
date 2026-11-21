// Package web embeds the management panel assets into the server binary. The
// frontend is plain HTML/CSS/JS with no external runtime dependency; the panel
// backend serves these files under /static/ and index.html as the SPA entry.
package web

import "embed"

// Assets is the embedded web/ directory (index.html, app.js, style.css).
//
//go:embed index.html app.js style.css
var Assets embed.FS
