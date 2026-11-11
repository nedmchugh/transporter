// OWNER is a placeholder for the GitHub account or organization that will
// host the project. Replace it everywhere with:
//   grep -rl 'github.com/OWNER/transporter' . | xargs sed -i 's#github.com/OWNER/#github.com/<owner>/#'
module github.com/OWNER/transporter

go 1.25.0

toolchain go1.27.4

require github.com/flynn/noise v1.1.0

require (
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
