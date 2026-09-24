//go:build !releaseassetsgen
// +build !releaseassetsgen

package releaseassets

// RuntimeAssetFiles is generated via `mutant gen --release-assets`.
var RuntimeAssetFiles = map[string]string{
	"darwin/amd64":  "data/darwin_amd64.bin",
	"linux/386":     "data/linux_386.bin",
	"linux/amd64":   "data/linux_amd64.bin",
	"linux/arm":     "data/linux_arm.bin",
	"linux/arm64":   "data/linux_arm64.bin",
	"windows/386":   "data/windows_386.bin",
	"windows/amd64": "data/windows_amd64.bin",
}
