module relay

go 1.22

// On Windows, run `go get github.com/williamfhe/godivert` to add the
// WinDivert binding used by the client. It is windows-only and will be
// skipped on Linux builds thanks to the build tag in client/main.go.

require github.com/williamfhe/godivert v0.0.0-20181229124620-a48c5b872c73
