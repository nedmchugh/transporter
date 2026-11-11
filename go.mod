// OWNER is a placeholder for the GitHub account or organization that will
// host the project. Replace it everywhere with:
//   grep -rl 'github.com/OWNER/transporter' . | xargs sed -i 's#github.com/OWNER/#github.com/<owner>/#'
module github.com/OWNER/transporter

go 1.25.0

toolchain go1.27.4

require (
	github.com/flynn/noise v1.1.0
	github.com/hashicorp/mdns v1.0.7
	golang.org/x/sys v0.47.0
	golang.org/x/term v0.45.0
	golang.org/x/text v0.41.0
	lukechampine.com/blake3 v1.4.1
)

require (
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/mod v0.38.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
)
