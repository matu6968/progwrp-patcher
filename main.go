package main

import (
	"archive/zip"
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Mapping of original DLL names to replacement names
var mapping map[string]string

// Base directory where helper blobs are stored
var blobsBaseDir string

// parseIni loads the DLL replacement mappings from the .ini file using a simple custom parser
func parseIni(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open ini file: %v", err)
	}
	defer file.Close()

	mapping = make(map[string]string)
	scanner := bufio.NewScanner(file)
	currentSection := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Check if this is a section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}

		// Parse key-value pairs
		if strings.Contains(line, "=") && currentSection != "" {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				// Only store ReplacementName entries
				if strings.ToLower(key) == "replacementname" {
					mapping[currentSection] = value
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading ini file: %v", err)
	}

	return nil
}

// detectArch reads the PE Machine field and returns "x86" or "x86_64"
func detectArch(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) < 0x40 || string(data[:2]) != "MZ" {
		return "", fmt.Errorf("not a PE file: %s", path)
	}
	e_lfanew := binary.LittleEndian.Uint32(data[0x3C:0x40])
	offset := e_lfanew + 4 // skip 'PE\0\0'
	machine := binary.LittleEndian.Uint16(data[offset : offset+2])
	switch machine {
	case 0x014c:
		return "x86", nil
	case 0x8664:
		return "x86_64", nil
	default:
		return fmt.Sprintf("unknown_0x%x", machine), nil
	}
}

// fetchBlobs downloads and extracts blobs-{arch}.zip to blobsBaseDir/{arch}
func fetchBlobs(repo, arch string) error {
	url := fmt.Sprintf("https://github.com/%s/releases/latest/download/progwrp_blobs-%s.zip", repo, arch)
	tmpFile, err := os.CreateTemp("", "progwrp_blobs-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to download blobs for %s: %s", arch, resp.Status)
	}

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	r, err := zip.OpenReader(tmpFile.Name())
	if err != nil {
		return err
	}
	defer r.Close()

	targetDir := filepath.Join(blobsBaseDir, arch)
	os.MkdirAll(targetDir, 0755)
	for _, f := range r.File {
		dpath := filepath.Join(targetDir, f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(dpath, f.Mode())
			continue
		}
		os.MkdirAll(filepath.Dir(dpath), 0755)
		src, err := f.Open()
		if err != nil {
			return err
		}
		dst, err := os.OpenFile(dpath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
		if err != nil {
			src.Close()
			return err
		}
		io.Copy(dst, src)
		src.Close()
		dst.Close()
	}
	return nil
}

// copyBlob copies a helper DLL from the arch-specific blobs directory
func copyBlob(arch, name, targetDir string) error {
	s := filepath.Join(blobsBaseDir, arch, name)
	d := filepath.Join(targetDir, name)
	in, err := os.Open(s)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(d, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func patchFile(path, arch string) error {
	// ... existing patch logic (OS version + imports) ...
	// After patching, deploy arch-specific helper libs
	dir := filepath.Dir(path)
	for _, rep := range mapping {
		if err := copyBlob(arch, rep, dir); err != nil {
			fmt.Printf("warning: failed to copy blob %s for %s: %v\n", rep, arch, err)
		} else {
			fmt.Printf("deployed %s (%s) to %s\n", rep, arch, dir)
		}
	}
	return nil
}

func main() {
	iniPath := flag.String("ini", "progwrp.ini", "path to ini file mapping DLLs")
	repo := flag.String("repo", "", "GitHub repo for blob releases (owner/repo)")
	input := flag.String("i", ".", "file or directory to patch")
	recurse := flag.Bool("r", false, "recurse into directories")
	flag.Parse()

	if *repo == "" {
		*repo = "matu6968/progwrp-patcher"
	}

	// Setup base blobs directory next to executable
	exePath, _ := os.Executable()
	blobsBaseDir = filepath.Join(filepath.Dir(exePath), "blobs")

	if err := parseIni(*iniPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Check if any .exe/.dll files were found before processing
	foundFiles := false
	filepath.Walk(*input, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info.IsDir() && path != *input && !*recurse {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".exe" || ext == ".dll" {
			foundFiles = true
		}
		return nil
	})

	if !foundFiles {
		fmt.Fprintf(os.Stderr, "Error: No .exe or .dll files found in %s\n", *input)
		os.Exit(1)
	}

	// Walk and patch
	filepath.Walk(*input, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info.IsDir() && path != *input && !*recurse {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".exe" && ext != ".dll" {
			return nil
		}

		arch, err := detectArch(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "arch detect failed for %s: %v\n", path, err)
			return nil
		}

		// Ensure blobs for this arch are present
		archDir := filepath.Join(blobsBaseDir, arch)
		if info, err := os.Stat(archDir); err != nil || !info.IsDir() {
			fmt.Printf("fetching %s blobs from GitHub (%s)...\n", arch, *repo)
			if err := fetchBlobs(*repo, arch); err != nil {
				fmt.Fprintf(os.Stderr, "error fetching %s blobs: %v\n", arch, err)
				return nil
			}
		}

		if err := patchFile(path, arch); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to patch %s: %v\n", path, err)
		}
		return nil
	})
}
