package recon

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"prowler/internal/config"
	"prowler/internal/output"
	"prowler/internal/util"
	"prowler/pkg/models"
)

type Phase3 struct {
	cfg      *config.Config
	resolver *util.DNSResolver
}

func NewPhase3(cfg *config.Config, resolver *util.DNSResolver) *Phase3 {
	return &Phase3{cfg: cfg, resolver: resolver}
}

func (p *Phase3) Name() string { return "SMTP Enumeration" }

func (p *Phase3) Run(ctx context.Context) (*models.Phase3Results, error) {
	output.PrintPhase(3, "SMTP ENUMERATION")

	results := &models.Phase3Results{}

	mxHosts, err := p.resolver.ResolveMX(p.cfg.TargetDomain)
	if err != nil || len(mxHosts) == 0 {
		log.Info().Msg("No MX records found")
		output.PrintDetail("No MX records found")
		return results, nil
	}

	results.MXHosts = mxHosts
	log.Info().Int("count", len(mxHosts)).Msg("Testing mail servers")

	for _, mx := range mxHosts {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		log.Info().Str("mx", mx).Msg("Testing SMTP commands")
		result := p.testSMTPCommands(mx)
		results.Results = append(results.Results, result)
	}

	// Print results
	if p.cfg.Verbosity >= 1 {
		output.PrintSection("PHASE 3 DETAILS")
		for _, r := range results.Results {
			fmt.Printf("   %s\n", r.MXHost)
			fmt.Printf("     VRFY: %s  EXPN: %s  RCPT: %s\n", r.VRFY, r.EXPN, r.RCPT)
		}
	}
	output.PrintDetail("%d MX hosts, %d tested",
		len(results.MXHosts), len(results.Results))

	return results, nil
}

func (p *Phase3) testSMTPCommands(mxHost string) models.SMTPResult {
	result := models.SMTPResult{
		MXHost: mxHost,
		VRFY:   models.SMTPNotImplemented,
		EXPN:   models.SMTPNotImplemented,
		RCPT:   models.SMTPNotImplemented,
	}

	// Resolve MX to IP
	ips, err := p.resolver.ResolveA(mxHost)
	if err != nil || len(ips) == 0 {
		log.Debug().Str("mx", mxHost).Msg("Cannot resolve MX host")
		result.VRFY = models.SMTPError
		result.EXPN = models.SMTPError
		result.RCPT = models.SMTPError
		return result
	}

	conn, err := net.DialTimeout("tcp", ips[0]+":25", 10*time.Second)
	if err != nil {
		log.Debug().Err(err).Str("mx", mxHost).Msg("SMTP connection failed")
		result.VRFY = models.SMTPError
		result.EXPN = models.SMTPError
		result.RCPT = models.SMTPError
		return result
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(conn)

	// Read banner
	readLine(reader)

	// EHLO
	writeLine(conn, "EHLO test.com")
	readMultiLine(reader)

	// Test VRFY
	result.VRFY = p.testVRFY(conn, reader)

	// Test EXPN
	result.EXPN = p.testEXPN(conn, reader)

	// Test RCPT TO
	result.RCPT = p.testRCPT(conn, reader)

	writeLine(conn, "QUIT")
	return result
}

func (p *Phase3) testVRFY(conn net.Conn, reader *bufio.Reader) models.SMTPCommandStatus {
	testUsers := []string{"root", "admin", "thisisnotarealuser12345", "postmaster"}
	responses := make(map[string]string)

	for _, user := range testUsers {
		writeLine(conn, fmt.Sprintf("VRFY %s", user))
		resp := readLine(reader)
		if len(resp) >= 3 {
			responses[user] = resp[:3]
		}
	}

	fakeCode := responses["thisisnotarealuser12345"]
	rootCode := responses["root"]
	postmasterCode := responses["postmaster"]

	// Different responses for real vs fake = VRFY working
	if strings.HasPrefix(fakeCode, "5") {
		if strings.HasPrefix(rootCode, "25") || strings.HasPrefix(postmasterCode, "25") {
			return models.SMTPAllowed
		}
	}

	if strings.HasPrefix(rootCode, "250") || strings.HasPrefix(postmasterCode, "250") {
		return models.SMTPAllowed
	}

	// All 5xx = prohibited
	allRejected := true
	for _, code := range responses {
		if !strings.HasPrefix(code, "5") {
			allRejected = false
			break
		}
	}
	if allRejected && len(responses) > 0 {
		return models.SMTPProhibited
	}

	return models.SMTPNotImplemented
}

func (p *Phase3) testEXPN(conn net.Conn, reader *bufio.Reader) models.SMTPCommandStatus {
	writeLine(conn, "EXPN root")
	resp := readLine(reader)

	if strings.HasPrefix(resp, "250") {
		return models.SMTPAllowed
	}
	if strings.HasPrefix(resp, "5") {
		return models.SMTPProhibited
	}
	return models.SMTPNotImplemented
}

func (p *Phase3) testRCPT(conn net.Conn, reader *bufio.Reader) models.SMTPCommandStatus {
	// Start mail transaction
	writeLine(conn, "MAIL FROM:<test@test.com>")
	resp := readLine(reader)
	if !strings.HasPrefix(resp, "250") {
		return models.SMTPNotImplemented
	}

	testAddresses := []string{
		fmt.Sprintf("postmaster@%s", p.cfg.TargetDomain),
		fmt.Sprintf("thisisnotreal12345@%s", p.cfg.TargetDomain),
		fmt.Sprintf("admin@%s", p.cfg.TargetDomain),
	}

	responses := make(map[string]string)
	for _, addr := range testAddresses {
		writeLine(conn, fmt.Sprintf("RCPT TO:<%s>", addr))
		resp := readLine(reader)
		if len(resp) >= 3 {
			responses[addr] = resp[:3]
		}

		// Reset if rejected
		if !strings.HasPrefix(resp, "250") {
			writeLine(conn, "RSET")
			readLine(reader)
			writeLine(conn, "MAIL FROM:<test@test.com>")
			readLine(reader)
		}
	}

	hasAccept := false
	hasReject := false
	for _, code := range responses {
		if strings.HasPrefix(code, "250") {
			hasAccept = true
		}
		if strings.HasPrefix(code, "5") {
			hasReject = true
		}
	}

	if hasAccept {
		return models.SMTPAllowed
	}
	if hasReject {
		return models.SMTPProhibited
	}

	return models.SMTPNotImplemented
}

func writeLine(conn net.Conn, line string) {
	conn.Write([]byte(line + "\r\n"))
}

func readLine(reader *bufio.Reader) string {
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func readMultiLine(reader *bufio.Reader) string {
	var result strings.Builder
	for {
		line, err := reader.ReadString('\n')
		result.WriteString(line)
		if err != nil || (len(line) >= 4 && line[3] == ' ') {
			break
		}
	}
	return result.String()
}
