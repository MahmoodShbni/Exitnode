module relay

go 1.23

require (
	// WinDivert 2.x binding (loads WinDivert.dll at runtime; windows-only).
	// Skipped on Linux builds via the build tag in client/main.go.
	github.com/imgk/divert-go v0.0.0-20250406082804-3cb755167a0a
	// recvmmsg batched I/O for the Linux server (-batch).
	golang.org/x/net v0.34.0
)

require golang.org/x/sys v0.31.0 // indirect
