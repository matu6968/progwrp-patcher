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
	"runtime"
	"strings"

	pefile "github.com/saferwall/pe"
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

// isProgwrpFile checks if a file is a progwrp replacement DLL that should be skipped
func isProgwrpFile(filename string) bool {
	// Get all replacement DLL names from the mapping
	for _, replacementName := range mapping {
		if strings.EqualFold(filepath.Base(filename), replacementName) {
			return true
		}
	}
	return false
}

// rvaToOffset converts a Relative Virtual Address (RVA) to a file offset using the section headers
func rvaToOffset(data []byte, rva uint32) (uint32, error) {
	if len(data) < 0x40 || string(data[:2]) != "MZ" {
		return 0, fmt.Errorf("not a PE file")
	}
	e_lfanew := binary.LittleEndian.Uint32(data[0x3C:0x40])
	sections := int(binary.LittleEndian.Uint16(data[e_lfanew+6 : e_lfanew+8]))
	optionalHeaderSize := binary.LittleEndian.Uint16(data[e_lfanew+0x14 : e_lfanew+0x16])
	sectionTableOffset := e_lfanew + 0x18 + uint32(optionalHeaderSize)

	for i := 0; i < sections; i++ {
		entry := sectionTableOffset + uint32(i*40)
		if int(entry+40) > len(data) {
			break
		}
		virtualAddress := binary.LittleEndian.Uint32(data[entry+12 : entry+16])
		sizeOfRawData := binary.LittleEndian.Uint32(data[entry+16 : entry+20])
		pointerToRawData := binary.LittleEndian.Uint32(data[entry+20 : entry+24])
		if rva >= virtualAddress && rva < virtualAddress+sizeOfRawData {
			return pointerToRawData + (rva - virtualAddress), nil
		}
	}
	return 0, fmt.Errorf("RVA 0x%x not found in any section", rva)
}

// patchVersionFields patches the PE Optional Header version fields for XP compatibility
func patchVersionFields(filePath string, debug bool) error {
	// Read the file data
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	var (
		optionalHeaderOffset uint32
		magic                uint16
	)
	// Find the file offset of the Optional Header
	// e_lfanew is at 0x3C
	if len(data) >= 0x3C+4 {
		e_lfanew := binary.LittleEndian.Uint32(data[0x3C:0x40])
		optionalHeaderOffset = e_lfanew + 0x18 // PE header + FileHeader (20 bytes) = 0x18
		magic = binary.LittleEndian.Uint16(data[optionalHeaderOffset : optionalHeaderOffset+2])
	}

	var majorOSVerOff, minorOSVerOff, majorSubVerOff, minorSubVerOff uint32
	if magic == 0x10b { // PE32
		majorOSVerOff = optionalHeaderOffset + 0x28
		minorOSVerOff = optionalHeaderOffset + 0x2A
		majorSubVerOff = optionalHeaderOffset + 0x30 // MajorSubsystemVersion
		minorSubVerOff = optionalHeaderOffset + 0x32 // MinorSubsystemVersion
	} else if magic == 0x20b { // PE32+
		majorOSVerOff = optionalHeaderOffset + 0x28
		minorOSVerOff = optionalHeaderOffset + 0x2A
		majorSubVerOff = optionalHeaderOffset + 0x30 // MajorSubsystemVersion
		minorSubVerOff = optionalHeaderOffset + 0x32 // MinorSubsystemVersion
	} else {
		return fmt.Errorf("unknown PE magic 0x%x, skipping version patch", magic)
	}

	if int(majorOSVerOff+2) <= len(data) && int(minorOSVerOff+2) <= len(data) && int(majorSubVerOff+2) <= len(data) && int(minorSubVerOff+2) <= len(data) {
		if debug {
			fmt.Printf("[DEBUG] Offsets (manual): majorOS=%#x minorOS=%#x majorSub=%#x minorSub=%#x\n", majorOSVerOff, minorOSVerOff, majorSubVerOff, minorSubVerOff)
			fmt.Printf("[DEBUG] Before: majorOS=%d minorOS=%d majorSub=%d minorSub=%d\n",
				binary.LittleEndian.Uint16(data[majorOSVerOff:majorOSVerOff+2]),
				binary.LittleEndian.Uint16(data[minorOSVerOff:minorOSVerOff+2]),
				binary.LittleEndian.Uint16(data[majorSubVerOff:majorSubVerOff+2]),
				binary.LittleEndian.Uint16(data[minorSubVerOff:minorSubVerOff+2]))
		}
		binary.LittleEndian.PutUint16(data[majorOSVerOff:majorOSVerOff+2], 5)
		binary.LittleEndian.PutUint16(data[minorOSVerOff:minorOSVerOff+2], 1)
		binary.LittleEndian.PutUint16(data[majorSubVerOff:majorSubVerOff+2], 5)
		binary.LittleEndian.PutUint16(data[minorSubVerOff:minorSubVerOff+2], 1)
		if debug {
			fmt.Printf("[DEBUG] After: majorOS=%d minorOS=%d majorSub=%d minorSub=%d\n",
				binary.LittleEndian.Uint16(data[majorOSVerOff:majorOSVerOff+2]),
				binary.LittleEndian.Uint16(data[minorOSVerOff:minorOSVerOff+2]),
				binary.LittleEndian.Uint16(data[majorSubVerOff:majorSubVerOff+2]),
				binary.LittleEndian.Uint16(data[minorSubVerOff:minorSubVerOff+2]))
		}
		fmt.Printf("patched subsystem/OS version to 5.1 (XP)\n")

		// Write the version-patched data back to the file
		if err := os.WriteFile(filePath, data, 0644); err != nil {
			return fmt.Errorf("failed to write version-patched file: %v", err)
		}
	}

	return nil
}

func patchFile(path, arch string, debug bool) error {
	// Read the entire file
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	// Open with saferwall/pe
	pe, err := pefile.New(path, &pefile.Options{Fast: false})
	if err != nil {
		return fmt.Errorf("failed to open PE file: %v", err)
	}
	if err := pe.Parse(); err != nil {
		return fmt.Errorf("failed to parse PE file: %v", err)
	}

	patched := false
	var importedDlls []string // Track which DLLs will be imported after patching
	var progwrpDlls []string  // Track only the progwrp DLLs we need to copy

	// Get import table bounds to constrain our search
	var importTableStart, importTableEnd uint32
	if pe.NtHeader.OptionalHeader != nil {
		if debug {
			fmt.Printf("[DEBUG] OptionalHeader type: %T\n", pe.NtHeader.OptionalHeader)
		}
		// Type assert to get the correct optional header type
		switch optHdr := pe.NtHeader.OptionalHeader.(type) {
		case *pefile.ImageOptionalHeader32:
			if debug {
				fmt.Printf("[DEBUG] Processing 32-bit PE (pointer), DataDirectory length: %d\n", len(optHdr.DataDirectory))
			}
			if len(optHdr.DataDirectory) > 1 {
				importTableDir := optHdr.DataDirectory[1] // Import table is directory entry 1
				importTableRVA := importTableDir.VirtualAddress
				importTableSize := importTableDir.Size

				if debug {
					fmt.Printf("[DEBUG] Import table RVA: 0x%x, Size: 0x%x\n", importTableRVA, importTableSize)
				}

				if importTableRVA != 0 && importTableSize != 0 {
					// Convert RVA to file offset
					if start, err := rvaToOffset(data, importTableRVA); err == nil {
						importTableStart = start
						importTableEnd = start + importTableSize
						if debug {
							fmt.Printf("[DEBUG] Import table bounds: 0x%x - 0x%x\n", importTableStart, importTableEnd)
						}
					} else if debug {
						fmt.Printf("[DEBUG] Failed to convert RVA to offset: %v\n", err)
					}
				}
			}
		case pefile.ImageOptionalHeader32:
			if debug {
				fmt.Printf("[DEBUG] Processing 32-bit PE (value), DataDirectory length: %d\n", len(optHdr.DataDirectory))
			}
			if len(optHdr.DataDirectory) > 1 {
				importTableDir := optHdr.DataDirectory[1] // Import table is directory entry 1
				importTableRVA := importTableDir.VirtualAddress
				importTableSize := importTableDir.Size

				if debug {
					fmt.Printf("[DEBUG] Import table RVA: 0x%x, Size: 0x%x\n", importTableRVA, importTableSize)
				}

				if importTableRVA != 0 && importTableSize != 0 {
					// Convert RVA to file offset
					if start, err := rvaToOffset(data, importTableRVA); err == nil {
						importTableStart = start
						importTableEnd = start + importTableSize
						if debug {
							fmt.Printf("[DEBUG] Import table bounds: 0x%x - 0x%x\n", importTableStart, importTableEnd)
						}
					} else if debug {
						fmt.Printf("[DEBUG] Failed to convert RVA to offset: %v\n", err)
					}
				}
			}
		case *pefile.ImageOptionalHeader64:
			if debug {
				fmt.Printf("[DEBUG] Processing 64-bit PE (pointer), DataDirectory length: %d\n", len(optHdr.DataDirectory))
			}
			if len(optHdr.DataDirectory) > 1 {
				importTableDir := optHdr.DataDirectory[1] // Import table is directory entry 1
				importTableRVA := importTableDir.VirtualAddress
				importTableSize := importTableDir.Size

				if debug {
					fmt.Printf("[DEBUG] Import table RVA: 0x%x, Size: 0x%x\n", importTableRVA, importTableSize)
				}

				if importTableRVA != 0 && importTableSize != 0 {
					// Convert RVA to file offset
					if start, err := rvaToOffset(data, importTableRVA); err == nil {
						importTableStart = start
						importTableEnd = start + importTableSize
						if debug {
							fmt.Printf("[DEBUG] Import table bounds: 0x%x - 0x%x\n", importTableStart, importTableEnd)
						}
					} else if debug {
						fmt.Printf("[DEBUG] Failed to convert RVA to offset: %v\n", err)
					}
				}
			}
		case pefile.ImageOptionalHeader64:
			if debug {
				fmt.Printf("[DEBUG] Processing 64-bit PE (value), DataDirectory length: %d\n", len(optHdr.DataDirectory))
			}
			if len(optHdr.DataDirectory) > 1 {
				importTableDir := optHdr.DataDirectory[1] // Import table is directory entry 1
				importTableRVA := importTableDir.VirtualAddress
				importTableSize := importTableDir.Size

				if debug {
					fmt.Printf("[DEBUG] Import table RVA: 0x%x, Size: 0x%x\n", importTableRVA, importTableSize)
				}

				if importTableRVA != 0 && importTableSize != 0 {
					// Convert RVA to file offset
					if start, err := rvaToOffset(data, importTableRVA); err == nil {
						importTableStart = start
						importTableEnd = start + importTableSize
						if debug {
							fmt.Printf("[DEBUG] Import table bounds: 0x%x - 0x%x\n", importTableStart, importTableEnd)
						}
					} else if debug {
						fmt.Printf("[DEBUG] Failed to convert RVA to offset: %v\n", err)
					}
				}
			}
		default:
			if debug {
				fmt.Printf("[DEBUG] Unknown OptionalHeader type: %T\n", optHdr)
			}
		}
	} else if debug {
		fmt.Printf("[DEBUG] OptionalHeader is nil\n")
	}

	for _, imp := range pe.Imports {
		origDLL := imp.Name
		lowDLL := strings.ToLower(origDLL)
		if replacement, ok := mapping[lowDLL]; ok {
			fmt.Printf("patching import: %s -> %s\n", origDLL, replacement)

			needle := []byte(origDLL + "\x00")
			replacementBytes := []byte(replacement + "\x00")
			if len(replacementBytes) > len(needle) {
				fmt.Printf("warning: replacement name too long for %s, skipping\n", origDLL)
				continue
			}

			// Count total occurrences in the file for debugging
			if debug {
				count := 0
				for i := uint32(0); i < uint32(len(data))-uint32(len(needle)); i++ {
					if string(data[i:i+uint32(len(needle))]) == string(needle) {
						count++
					}
				}
				fmt.Printf("[DEBUG] Found %d total occurrences of %s in file\n", count, origDLL)
			}

			foundAndPatched := false
			// Search within import table bounds if available, otherwise full file
			searchStart := uint32(0)
			searchEnd := uint32(len(data))

			if importTableStart != 0 && importTableEnd != 0 && importTableEnd > importTableStart {
				// Expand search to include nearby sections that might contain import strings
				// Import table usually just contains descriptors, strings are in .rdata/.idata
				searchStart = importTableStart
				// Expand search area to cover potential string sections
				if importTableEnd+0x10000 < uint32(len(data)) {
					searchEnd = importTableEnd + 0x10000 // Search 64KB after import table
				} else {
					searchEnd = uint32(len(data))
				}
				if debug {
					fmt.Printf("[DEBUG] Searching for %s in expanded import region 0x%x - 0x%x\n", origDLL, searchStart, searchEnd)
				}
			} else {
				if debug {
					fmt.Printf("[DEBUG] Searching for %s in entire file (import table bounds not available)\n", origDLL)
				}
			}

			for i := searchStart; i < searchEnd-uint32(len(needle)); i++ {
				if string(data[i:i+uint32(len(needle))]) == string(needle) {
					if debug {
						fmt.Printf("[DEBUG] Found %s at offset 0x%x\n", origDLL, i)
					}
					copy(data[i:i+uint32(len(replacementBytes))], replacementBytes)
					for j := i + uint32(len(replacementBytes)); j < i+uint32(len(needle)); j++ {
						data[j] = 0
					}
					foundAndPatched = true
					patched = true
					if debug {
						// Verify the replacement
						replacedName := string(data[i : i+uint32(len(replacement))])
						fmt.Printf("[DEBUG] Verified replacement: %s -> %s\n", origDLL, replacedName)
					}
					break // Only patch first occurrence within region
				}
			}

			if !foundAndPatched {
				if debug {
					fmt.Printf("[DEBUG] Not found in constrained region, trying full file search for %s\n", origDLL)
				}
				// Fallback to full file search if constrained search failed
				for i := uint32(0); i < uint32(len(data))-uint32(len(needle)); i++ {
					if string(data[i:i+uint32(len(needle))]) == string(needle) {
						if debug {
							fmt.Printf("[DEBUG] Found %s at offset 0x%x (full file search)\n", origDLL, i)
						}
						copy(data[i:i+uint32(len(replacementBytes))], replacementBytes)
						for j := i + uint32(len(replacementBytes)); j < i+uint32(len(needle)); j++ {
							data[j] = 0
						}
						foundAndPatched = true
						patched = true
						if debug {
							// Verify the replacement
							replacedName := string(data[i : i+uint32(len(replacement))])
							fmt.Printf("[DEBUG] Verified replacement: %s -> %s (full file search)\n", origDLL, replacedName)
						}
						break // Only patch first occurrence
					}
				}
			}

			if !foundAndPatched {
				fmt.Printf("warning: could not find %s in import table, skipping\n", origDLL)
				continue
			}

			// Add the replacement DLL to our list
			importedDlls = append(importedDlls, strings.ToLower(replacement))
			progwrpDlls = append(progwrpDlls, strings.ToLower(replacement))
		} else {
			// Keep track of DLLs that weren't replaced
			importedDlls = append(importedDlls, lowDLL)
		}
	}
	if patched {
		// Write to a new file to avoid file lock issues
		outPath := path[:len(path)-len(filepath.Ext(path))] + "_patched" + filepath.Ext(path)
		if err := os.WriteFile(outPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write patched file: %v", err)
		}
		fmt.Printf("successfully patched %s -> %s\n", path, outPath)

		// Copy progwrp DLLs that are imported by the patched file
		if debug {
			fmt.Printf("[DEBUG] DLLs imported by patched file: ")
			for _, dll := range importedDlls {
				fmt.Printf("%s ", dll)
			}
			fmt.Printf("\n[DEBUG] Progwrp DLLs to copy: ")
			for _, dll := range progwrpDlls {
				fmt.Printf("%s ", dll)
			}
			fmt.Printf("\n[DEBUG] Mapping contents:\n")
			for k, v := range mapping {
				fmt.Printf("  key: '%s' (len=%d), value: '%s' (len=%d)\n", k, len(k), v, len(v))
			}
		}
		fmt.Printf("Copying progwrp DLLs: ")
		for _, dll := range progwrpDlls {
			if debug {
				fmt.Printf("%s ", dll)
			}
			if err := copyBlob(arch, dll, filepath.Dir(outPath)); err != nil {
				fmt.Printf("\nwarning: failed to copy blob %s for %s: %v\n", dll, arch, err)
			} else {
				fmt.Printf("\ndeployed %s (%s) to %s\n", dll, arch, filepath.Dir(outPath))
			}
		}

		// Patch PE Optional Header for XP compatibility - done separately to avoid file locking
		if err := patchVersionFields(outPath, debug); err != nil {
			fmt.Printf("warning: failed to patch version fields: %v\n", err)
		}
	} else {
		fmt.Printf("no imports to patch in %s\n", path)
	}
	return nil
}

func main() {
	iniPath := flag.String("ini", "progwrp.ini", "path to ini file mapping DLLs")
	repo := flag.String("repo", "", "GitHub repo for blob releases (owner/repo)")
	input := flag.String("i", ".", "file or directory to patch")
	recurse := flag.Bool("r", false, "recurse into directories")
	debug := flag.Bool("debug", false, "enable debug output")
	flag.Parse()

	// Check if running on Windows
	// in the future once go 1.10 support will work then also check if it's really running on XP and display this message if not
	if runtime.GOOS != "windows" {
		fmt.Println("Note: This tool patches Windows executables for Windows XP compatibility.")
		fmt.Println("Since you're not running on Windows, you'll need to copy the patched files")
		fmt.Println("and progwrp DLLs to your target Windows machine to use them.")
		fmt.Println()
	}

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

		// Skip progwrp replacement DLLs
		if isProgwrpFile(path) {
			fmt.Printf("skipping progwrp file: %s\n", path)
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

		if err := patchFile(path, arch, *debug); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to patch %s: %v\n", path, err)
		}
		return nil
	})
}
