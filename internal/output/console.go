package output

import (
	"fmt"
	"strings"
)

const banner = `
 ______                 _
(_____ \               | |
 _____) )___ ___  _ _ _| | _____  ____
|  ____/ ___) _ \| | | | || ___ |/ ___)
| |   | |  | |_| | | | | || ____| |
|_|   |_|   \___/ \___/ \_)_____)_|
       #Waffl3ss            v0.6
`

func PrintStartBanner() {
	fmt.Print(banner)
}

// PrintPhase prints a phase header like "[+] PHASE 1: DOMAIN IDENTIFICATION"
func PrintPhase(phase int, title string) {
	fmt.Printf("\n[+] PHASE %d: %s\n", phase, title)
}

// PrintInfo prints an info header like "[i] PROWLER - RECONNAISSANCE"
func PrintInfo(title string) {
	fmt.Printf("\n[i] %s\n", title)
}

// PrintWarn prints a warning like "[!] message"
func PrintWarn(title string) {
	fmt.Printf("[!] %s\n", title)
}

// PrintDetail prints a detail line like "-- key: value"
func PrintDetail(format string, args ...interface{}) {
	fmt.Printf("-- "+format+"\n", args...)
}

// PrintSub prints a sub-detail line like "   - item"
func PrintSub(format string, args ...interface{}) {
	fmt.Printf("   - "+format+"\n", args...)
}

// PrintResult is an alias for PrintDetail for backwards compatibility.
func PrintResult(label, value string) {
	fmt.Printf("-- %s: %s\n", label, value)
}

// PrintDivider prints a thin divider line.
func PrintDivider() {
	fmt.Println(strings.Repeat("-", 80))
}

// PrintTableHeader prints a formatted table header with divider.
func PrintTableHeader(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
	PrintDivider()
}

// PrintSection is for verbose detailed output sections (shown with -v).
func PrintSection(title string) {
	fmt.Printf("\n[v] %s\n", title)
}

// PrintSummary prints a brief summary line.
func PrintSummary(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}
