package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	"github.com/shehzade/ntds-to-bloodhound/pkg/acl"
	"github.com/shehzade/ntds-to-bloodhound/pkg/ad"
	bhv4 "github.com/shehzade/ntds-to-bloodhound/pkg/bloodhound/v4"
	bhv5 "github.com/shehzade/ntds-to-bloodhound/pkg/bloodhound/v5"
	"github.com/shehzade/ntds-to-bloodhound/pkg/crypto"
	"github.com/shehzade/ntds-to-bloodhound/pkg/ese"
	"github.com/shehzade/ntds-to-bloodhound/pkg/registry"
)

const banner = `
======================================================================
  ntds-to-bloodhound - Fast Offline AD NTDS.DIT to BloodHound Parser
  Version: 1.0.0 (Pure Go | Zero Cgo | Ultra-Fast ESE Engine)
======================================================================`

func printUsage() {
	fmt.Println(banner)
	fmt.Print(`
USAGE:
    ntds-to-bloodhound [OPTIONS]

REQUIRED FLAGS:
    -n, --ntds PATH           Path to the offline ntds.dit database file
    -s, --system PATH         Path to the offline SYSTEM registry hive file

OPTIONAL FLAGS:
    -o, --out PATH            Output directory for generated BloodHound files (default: "./output")
    -f, --format FORMAT       Output format: "v4" (Legacy), "v5" (Community Edition), or "all" (default: "all")
    -d, --dump-hashes PATH    Optional path to write a secretsdump-compatible credential file
        --domain FQDN         Override Active Directory domain FQDN if not auto-detected
        --zip                 Package v5 output into standard BloodHound ingestion ZIP archive (default: true)
    -v, --verbose             Enable detailed debug logging and object parsing metrics
    -h, --help                Show help information
`)
}

func main() {
	var (
		ntdsPath       string
		sysPath        string
		outDir         string
		format         string
		dumpHashesPath string
		domainOverride string
		zipPackage     bool
		verbose        bool
		help           bool
	)

	flag.StringVar(&ntdsPath, "ntds", "", "Path to the offline ntds.dit database file")
	flag.StringVar(&ntdsPath, "n", "", "Path to the offline ntds.dit database file (shorthand)")

	flag.StringVar(&sysPath, "system", "", "Path to the offline SYSTEM registry hive file")
	flag.StringVar(&sysPath, "s", "", "Path to the offline SYSTEM registry hive file (shorthand)")

	flag.StringVar(&outDir, "out", "./output", "Output directory for generated BloodHound files")
	flag.StringVar(&outDir, "o", "./output", "Output directory (shorthand)")

	flag.StringVar(&format, "format", "all", "Output format: v4, v5, or all")
	flag.StringVar(&format, "f", "all", "Output format (shorthand)")

	flag.StringVar(&dumpHashesPath, "dump-hashes", "", "Path to write secretsdump-compatible credential file")
	flag.StringVar(&dumpHashesPath, "d", "", "Path to write credential file (shorthand)")

	flag.StringVar(&domainOverride, "domain", "", "Override Active Directory domain FQDN")
	flag.BoolVar(&zipPackage, "zip", true, "Package v5 output into BloodHound ZIP archive")

	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&verbose, "v", false, "Enable verbose logging (shorthand)")

	flag.BoolVar(&help, "help", false, "Show help information")
	flag.BoolVar(&help, "h", false, "Show help information (shorthand)")

	flag.Parse()

	if help || ntdsPath == "" || sysPath == "" {
		printUsage()
		if help {
			os.Exit(0)
		}
		os.Exit(1)
	}

	formatLower := strings.ToLower(strings.TrimSpace(format))
	if formatLower != "v4" && formatLower != "v5" && formatLower != "all" {
		fmt.Printf("[-] Error: unsupported format %q (must be \"v4\", \"v5\", or \"all\")\n", format)
		os.Exit(1)
	}

	startTime := time.Now()
	fmt.Println(banner)
	fmt.Println()

	if _, err := os.Stat(ntdsPath); os.IsNotExist(err) {
		fmt.Printf("[-] Error: ntds.dit file not found: %s\n", ntdsPath)
		os.Exit(1)
	}
	if _, err := os.Stat(sysPath); os.IsNotExist(err) {
		fmt.Printf("[-] Error: SYSTEM hive file not found: %s\n", sysPath)
		os.Exit(1)
	}

	fmt.Printf("[*] [1/5] Extracting BootKey from SYSTEM hive: %s\n", sysPath)
	bootKey, err := registry.ExtractBootKey(sysPath)
	if err != nil {
		fmt.Printf("[-] Failed to extract BootKey: %v\n", err)
		os.Exit(1)
	}
	bootKeyHex := hex.EncodeToString(bootKey)
	fmt.Printf("[+] SysKey / BootKey derived: 0x%s\n", bootKeyHex)

	fmt.Printf("[*] [2/5] Opening ESE database: %s\n", ntdsPath)
	db, err := ese.OpenDB(ntdsPath)
	if err != nil {
		fmt.Printf("[-] Failed to open ESE database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	fmt.Println("[*] [3/5] Locating and decrypting Password Encryption Keys (PEK)...")
	cryptoEngine := crypto.NewCryptoEngine(bootKey)

	pekFound := false
	err = db.StreamTable("datatable", func(row *ordereddict.Dict) error {
		if pekFound {
			return nil
		}
		if val, ok := row.Get("ATTk590689"); ok && val != nil {
			if rawHex, ok := val.(string); ok && len(rawHex) > 0 {
				if b, err := hex.DecodeString(rawHex); err == nil {
					if err := cryptoEngine.ParsePekList(b); err == nil {
						pekFound = true
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		fmt.Printf("[-] Error scanning for pekList: %v\n", err)
		os.Exit(1)
	}
	if !pekFound || len(cryptoEngine.PEKList) == 0 {
		fmt.Println("[-] Warning: No valid pekList found or decrypted! Account hashes will not be decrypted.")
	} else {
		for keyID, keyBytes := range cryptoEngine.PEKList {
			pekHex := hex.EncodeToString(keyBytes)
			fmt.Printf("[+] PEK # %d found and decrypted: %s\n", keyID, pekHex)
		}
	}

	if verbose {
		fmt.Println("[*] Initializing Security Descriptor cache from sd_table...")
	}
	secEngine, err := acl.NewSecurityEngine(db)
	if err != nil {
		fmt.Printf("[-] Failed to load security descriptors: %v\n", err)
		os.Exit(1)
	}
	if verbose {
		fmt.Printf("[+] Cached %d binary security descriptors\n", secEngine.Count())
	}

	fmt.Println("[*] [4/5] Reconstructing Active Directory hierarchy, group memberships, and ACLs...")
	assembler := ad.NewAssembler(db, cryptoEngine, secEngine, domainOverride)
	if err := assembler.Assemble(); err != nil {
		fmt.Printf("[-] Assembly failed: %v\n", err)
		os.Exit(1)
	}
	snap := assembler.Snapshot

	userCount := len(snap.Users)
	groupCount := len(snap.Groups)
	computerCount := len(snap.Computers)
	ouCount := len(snap.OUs)
	domainCount := len(snap.Domains)

	var credsDecrypted int
	for _, u := range snap.Users {
		if u.NTHash != "" {
			credsDecrypted++
		}
	}

	var totalMemberships int
	for _, g := range snap.Groups {
		totalMemberships += len(g.Members)
	}

	var totalAces int
	for _, u := range snap.Users {
		totalAces += len(u.Aces)
	}
	for _, g := range snap.Groups {
		totalAces += len(g.Aces)
	}
	for _, c := range snap.Computers {
		totalAces += len(c.Aces)
	}
	for _, d := range snap.Domains {
		totalAces += len(d.Aces)
	}
	for _, o := range snap.OUs {
		totalAces += len(o.Aces)
	}

	if dumpHashesPath != "" {
		fmt.Printf("[*] Writing decrypted credentials to %s...\n", dumpHashesPath)
		if dir := filepath.Dir(dumpHashesPath); dir != "" {
			_ = os.MkdirAll(dir, 0755)
		}
		var sb strings.Builder
		for _, u := range snap.Users {
			sam := u.Properties["samaccountname"].(string)
			rid := 0
			parts := strings.Split(u.ObjectIdentifier, "-")
			if len(parts) > 0 {
				fmt.Sscanf(parts[len(parts)-1], "%d", &rid)
			}
			nthash := u.NTHash
			if nthash == "" {
				nthash = crypto.EmptyNTHash
			}
			sb.WriteString(fmt.Sprintf("%s:%d:%s:%s:::\n",
				sam, rid, crypto.EmptyLMHash, nthash))
		}
		for _, c := range snap.Computers {
			sam := c.Properties["samaccountname"].(string)
			rid := 0
			parts := strings.Split(c.ObjectIdentifier, "-")
			if len(parts) > 0 {
				fmt.Sscanf(parts[len(parts)-1], "%d", &rid)
			}
			nthash := c.NTHash
			if nthash == "" {
				nthash = crypto.EmptyNTHash
			}
			sb.WriteString(fmt.Sprintf("%s:%d:%s:%s:::\n",
				sam, rid, crypto.EmptyLMHash, nthash))
		}
		totalCreds := len(snap.Users) + len(snap.Computers)
		if err := os.WriteFile(dumpHashesPath, []byte(sb.String()), 0600); err != nil {
			fmt.Printf("[-] Failed to write credentials file: %v\n", err)
		} else {
			fmt.Printf("[+] Successfully wrote %d credentials to %s\n", totalCreds, dumpHashesPath)
		}
	}

	fmt.Printf("[*] [5/5] Exporting BloodHound files (format: %s) to %s...\n", formatLower, outDir)

	var createdFiles []string

	if formatLower == "v4" || formatLower == "all" {
		targetV4Dir := outDir
		if formatLower == "all" {
			targetV4Dir = filepath.Join(outDir, "v4")
		}
		v4Writer := bhv4.NewWriter(targetV4Dir)
		if err := v4Writer.WriteSnapshot(snap); err != nil {
			fmt.Printf("[-] Error writing v4 files: %v\n", err)
			os.Exit(1)
		}
		createdFiles = append(createdFiles, filepath.Join(targetV4Dir, "{users,groups,computers,domains,ous}.json"))
		fmt.Printf("[+] BloodHound Legacy (v4) JSON files written to %s\n", targetV4Dir)
	}

	if formatLower == "v5" || formatLower == "all" {
		targetV5Dir := outDir
		if formatLower == "all" {
			targetV5Dir = filepath.Join(outDir, "v5")
		}
		v5Writer := bhv5.NewWriter(targetV5Dir)
		if err := v5Writer.WriteSnapshot(snap); err != nil {
			fmt.Printf("[-] Error writing v5 files: %v\n", err)
			os.Exit(1)
		}
		createdFiles = append(createdFiles, filepath.Join(targetV5Dir, "{users,groups,computers,domains,ous}.json"))
		fmt.Printf("[+] BloodHound Community Edition (v5) JSON files written to %s\n", targetV5Dir)

		if zipPackage {
			zipPath := filepath.Join(targetV5Dir, bhv5.GenerateZipFilename())
			if err := bhv5.CreateZipArchive(snap, zipPath); err != nil {
				fmt.Printf("[-] Error creating ZIP archive: %v\n", err)
			} else {
				createdFiles = append(createdFiles, zipPath)
				fmt.Printf("[+] BloodHound CE Ingestion Archive created: %s\n", zipPath)
			}
		}
	}

	elapsed := time.Since(startTime)

	fmt.Println()
	fmt.Println("======================================================================")
	fmt.Println("                     EXTRACTION METRICS & SUMMARY                     ")
	fmt.Println("======================================================================")
	fmt.Printf("  Target Domain Name       : %s\n", snap.DomainName)
	fmt.Printf("  Target Domain SID        : %s\n", snap.DomainSID)
	fmt.Printf("  Total Users Extracted    : %d\n", userCount)
	fmt.Printf("  Total Groups Extracted   : %d\n", groupCount)
	fmt.Printf("  Total Computers Extracted: %d\n", computerCount)
	fmt.Printf("  Total OUs Extracted      : %d\n", ouCount)
	fmt.Printf("  Domains Extracted        : %d\n", domainCount)
	fmt.Printf("  Decrypted NT Hashes      : %d / %d\n", credsDecrypted, userCount)
	fmt.Printf("  Group Memberships Linked : %d\n", totalMemberships)
	fmt.Printf("  BloodHound Edges (ACEs)  : %d\n", totalAces)
	fmt.Printf("  Total Elapsed Processing : %s\n", elapsed)
	fmt.Println("======================================================================")
	fmt.Println("[+] Done! BloodHound collection complete.")
}
