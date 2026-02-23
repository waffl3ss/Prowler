# Prowler

A single-binary OSINT toolkit written in Go for authorized security assessments. Performs comprehensive domain reconnaissance and document metadata extraction to identify usernames, software versions, and organizational intel from publicly available data.

> **Disclaimer:** This toolkit is intended for authorized penetration testing and security research only. Always obtain proper authorization before scanning any target.

## Features

### Recon (Phases 1-5)

| Phase | Name | Description |
|-------|------|-------------|
| 1 | **Domain Identification** | Certificate transparency logs (crt.sh), DNS enumeration, subdomain bruteforce with SecLists support, WHOIS/RDAP lookups, netblock/CIDR discovery |
| 2 | **Zone Transfers** | AXFR checks against all discovered nameservers |
| 3 | **SMTP Enumeration** | VRFY, EXPN, and RCPT TO command testing with catch-all detection |
| 4 | **Web App Discovery** | HTTP/HTTPS scanning with title extraction, technology fingerprinting, dedup by final URL |
| 5 | **Cloud Keywords** | Generates keyword lists for cloud_enum from domain and subdomain patterns |

### Scan (Phase 6)

| Feature | Description |
|---------|-------------|
| **Browser Dorking** | Uses go-rod with stealth (anti-detection) to search Google, Bing, and DuckDuckGo |
| **CAPTCHA Handling** | Headed mode with "Press ENTER" prompt before launch, engine-specific CAPTCHA detection with timeout |
| **Document Download** | Concurrent downloads with MD5 hashing (PDF, DOC/DOCX, XLS/XLSX, PPT/PPTX) |
| **Metadata Extraction** | Native Go extractors for PDF (pdfcpu) and Office XML (archive/zip), optional exiftool |
| **Intelligence** | Extracts usernames, software versions, creation dates with software name filtering |

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/prowler.git
cd prowler

# Build for current platform
go build -o prowler .

# Cross-compile all platforms
make all
```

### Requirements
- Go 1.22+ (build only)
- Chrome or Chromium (required for `scan` and `full` — auto-downloads Chromium if not found)
- SecLists (optional, for extended subdomain wordlists)
- exiftool (optional, for richer document metadata)

```bash
# Install exiftool (optional)
sudo apt-get install libimage-exiftool-perl
```

## Usage

### Recon (Phases 1-5)
```bash
# Full recon
./prowler recon example.com

# Skip specific phases
./prowler recon example.com --skip-phase2 --skip-phase3

# Custom wordlist and resolvers
./prowler recon example.com -w /path/to/wordlist.txt --resolvers 8.8.8.8,1.1.1.1

# Skip bruteforce entirely
./prowler recon example.com --no-bruteforce

# Verbose output (show per-phase details)
./prowler recon example.com -v
```

### Scan (Phase 6 - Document Metadata)
```bash
# Headless mode, all search engines
./prowler scan example.com

# Headed mode for manual CAPTCHA solving (prompts before browser launch)
./prowler scan example.com --headed

# Slower queries, Google only
./prowler scan example.com --delay 20 --no-bing --no-ddg

# Skip search, process a URL list directly
./prowler scan --url-list urls.txt

# Verbose output (show per-document metadata + summary table)
./prowler scan example.com -v
```

### Full Pipeline
```bash
# Run everything
./prowler full example.com

# Full pipeline with custom options
./prowler full example.com --headed --delay 15 --skip-phase3 -o results/
```

### Global Options
```
-o, --output     Output directory (default: prowler_output)
-v, --verbose    Show detailed per-phase output
    --debug      Show debug output (zerolog)
-t, --threads    Max concurrent goroutines (default: 20)
    --timeout    Network timeout in seconds (default: 30)
```

### Recon Options
```
    --skip-phase2      Skip DNS zone transfer checks
    --skip-phase3      Skip SMTP enumeration
    --skip-phase4      Skip web application discovery
    --skip-phase5      Skip cloud enum keyword generation
-w, --wordlist         Path to subdomain wordlist (default: built-in 184-word list)
    --no-bruteforce    Skip subdomain bruteforcing entirely
    --resolvers        Comma-separated custom DNS resolvers
```

### Scan Options
```
    --headed             Launch visible browser for manual CAPTCHA solving
-d, --delay              Min delay between search queries in seconds (default: 10)
    --delay-max          Max delay between search queries in seconds (default: 15)
    --no-google          Skip Google
    --no-bing            Skip Bing
    --no-ddg             Skip DuckDuckGo
    --max-downloads      Max documents to download (default: 100)
-u, --url-list           File with URLs to process directly (skips search)
    --max-pages          Max result pages per dork per engine (default: 2)
    --download-workers   Concurrent download goroutines (default: 5)
    --no-exiftool        Disable exiftool even if available
```

## Output

Results are saved to `prowler_output/` by default:

```
prowler_output/
├── results.json                # Unified results (all phases)
├── phase1_domains.json         # Domain details with IPs, registrar, netblocks
├── phase1_domains.txt          # Plain domain list
├── phase1_domains.csv          # Domain summary table
├── phase2_zone_transfers.json  # Zone transfer results
├── phase3_smtp.json            # SMTP enumeration results
├── phase4_webapps.json         # Discovered web applications
├── phase4_webapps.csv          # Web app summary table
├── phase4_urls.txt             # Web app URL list
├── phase5_cloud_keywords.txt   # Keywords for cloud_enum
├── metadata_full.json          # Full document metadata
├── metadata_summary.csv        # Metadata CSV (URL, type, hash, author, software, dates, title)
├── extracted_usernames.txt     # Unique usernames from documents
├── extracted_software.txt      # Unique software from documents
└── documents/                  # Downloaded document files
```

### Output Format Tags

Prowler uses tagged output for clean readability:

| Tag | Meaning |
|-----|---------|
| `[i]` | Info header (tool start/complete, section transitions) |
| `[+]` | Phase header (phase start) |
| `[v]` | Verbose detail section (only with `-v`) |
| `[!]` | Warning (CAPTCHA detected, errors) |
| `--` | Detail/result line |

### Verbosity Levels

| Flag | Level | Shows |
|------|-------|-------|
| *(none)* | Quiet | Phase summaries, stats, final results |
| `-v` | Verbose | Per-phase details, per-document metadata, summary table, intelligence breakdown |
| `--debug` | Debug | All verbose output + zerolog debug messages |

## License

This project is for educational and authorized security testing purposes only.
