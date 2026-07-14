package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var wasmMagic = []byte{0x00, 0x61, 0x73, 0x6d}

func main() {
	repoRoot, err := resolveRepoRoot()
	if err != nil {
		log.Fatal(err)
	}

	addr := flag.String("addr", "127.0.0.1:8123", "listen address")
	dir := flag.String("dir", filepath.Join("examples", "wasm-repl"), "directory containing index.html, wasm_exec.js, and mutant_repl.wasm")
	flag.Parse()

	resolvedDir := *dir
	if !filepath.IsAbs(resolvedDir) {
		resolvedDir = filepath.Join(repoRoot, resolvedDir)
	}

	if err := prepareExampleFiles(repoRoot, resolvedDir); err != nil {
		log.Fatal(err)
	}

	absDir, err := filepath.Abs(resolvedDir)
	if err != nil {
		log.Fatalf("resolve example directory: %v", err)
	}

	if mime.TypeByExtension(".wasm") == "" {
		if err := mime.AddExtensionType(".wasm", "application/wasm"); err != nil {
			log.Fatalf("register wasm content type: %v", err)
		}
	}

	server := &http.Server{
		Addr:    *addr,
		Handler: handler(absDir),
	}

	url := fmt.Sprintf("http://%s/", *addr)
	log.Printf("serving Mutant wasm REPL from %s", absDir)
	log.Printf("open %s", url)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server failed: %v", err)
	}
}

func resolveRepoRoot() (string, error) {
	cmd := exec.Command("go", "env", "GOMOD")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("resolve module root via go env GOMOD: %w", err)
	}

	gomod := strings.TrimSpace(string(output))
	if gomod == "" || gomod == os.DevNull {
		return "", fmt.Errorf("go env GOMOD did not return a module path")
	}

	return filepath.Dir(gomod), nil
}

func prepareExampleFiles(repoRoot string, dir string) error {
	required := []string{"index.html"}
	for _, name := range required {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("required file missing: %s", path)
			}
			return fmt.Errorf("stat %s: %w", path, err)
		}
		if info.IsDir() {
			return fmt.Errorf("expected file but found directory: %s", path)
		}
	}

	if err := syncWasmExec(dir); err != nil {
		return err
	}

	if err := ensureWasmBinary(repoRoot, dir); err != nil {
		return err
	}

	return nil
}

func syncWasmExec(dir string) error {
	goRootBytes, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		return fmt.Errorf("resolve GOROOT: %w", err)
	}

	goRoot := strings.TrimSpace(string(goRootBytes))
	source := filepath.Join(goRoot, "lib", "wasm", "wasm_exec.js")
	if _, err := os.Stat(source); err != nil {
		source = filepath.Join(goRoot, "misc", "wasm", "wasm_exec.js")
		if _, fallbackErr := os.Stat(source); fallbackErr != nil {
			return fmt.Errorf("locate wasm_exec.js under GOROOT: %w", err)
		}
	}

	target := filepath.Join(dir, "wasm_exec.js")
	if err := copyFile(source, target); err != nil {
		return fmt.Errorf("sync wasm_exec.js: %w", err)
	}

	return nil
}

func ensureWasmBinary(repoRoot string, dir string) error {
	target := filepath.Join(dir, "mutant_repl.wasm")
	valid, err := isWasmBinary(target)
	if err == nil && valid {
		return nil
	}

	log.Printf("refreshing wasm artifact at %s", target)
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", target, "./cmd/replwasm")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm", "CGO_ENABLED=0")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build wasm repl artifact: %w", err)
	}

	valid, err = isWasmBinary(target)
	if err != nil {
		return fmt.Errorf("validate rebuilt wasm artifact: %w", err)
	}
	if !valid {
		return fmt.Errorf("rebuilt artifact is not a valid wasm binary: %s", target)
	}

	return nil
}

func isWasmBinary(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	header := make([]byte, len(wasmMagic))
	if _, err := io.ReadFull(file, header); err != nil {
		return false, err
	}

	return bytes.Equal(header, wasmMagic), nil
}

func copyFile(source string, target string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(target)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}

	if err := out.Close(); err != nil {
		return err
	}

	return nil
}

func handler(root string) http.Handler {
	fileServer := http.FileServer(http.Dir(root))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, filepath.Join(root, "index.html"))
			return
		}

		if strings.EqualFold(filepath.Ext(r.URL.Path), ".wasm") {
			w.Header().Set("Content-Type", "application/wasm")
		}

		fileServer.ServeHTTP(w, r)
	})
}
