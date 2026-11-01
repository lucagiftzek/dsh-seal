// Package client embeds the compiled browser scripts (built by build.mjs from
// src/*.ts with esbuild; the outputs are committed so `go build` needs no Node).
package client

import _ "embed"

//go:embed dist/boot.js
var Boot []byte

//go:embed dist/sw.js
var SW []byte

//go:embed dist/sw-kill.js
var KillSW []byte
