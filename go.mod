module relay

go 1.23

// WinDivert 2.x binding (loads WinDivert.dll at runtime; windows-only).
// It is skipped on Linux builds thanks to the build tag in client/main.go.
require github.com/imgk/divert-go v0.0.0-20250406082804-3cb755167a0a

require golang.org/x/sys v0.31.0 // indirect
