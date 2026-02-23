package recon

import (
	"bufio"
	"os"

	"github.com/rs/zerolog/log"
)

var seclistsPaths = []string{
	"/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
	"/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
	"./subdomains-top1million-5000.txt",
}

var builtinWordlist = []string{
	"www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
	"cpanel", "whm", "autodiscover", "autoconfig", "admin",
	"api", "dev", "staging", "test", "portal", "vpn", "remote",
	"secure", "app", "apps", "cloud", "store", "shop", "blog",
	"forum", "support", "help", "docs", "status", "cdn", "static",
	"localhost", "webdisk", "ns", "ns3", "ns4", "email", "direct",
	"direct-connect", "cpcontacts", "cpcalendars",
	"mobile", "m", "wiki", "news", "beta", "alpha",
	"demo", "sandbox", "uat", "backup", "db", "database",
	"mysql", "sql", "files", "upload", "downloads",
	"assets", "media", "images", "img", "css", "js",
	"login", "signin", "signup", "register", "sso",
	"dashboard", "panel", "console", "control",
	"administrator", "root", "system", "internal",
	"private", "public", "external", "customer", "client",
	"partner", "vendor", "supplier", "git", "svn",
	"ci", "jenkins", "gitlab", "github", "bitbucket",
	"jira", "confluence", "kb", "helpdesk",
	"ticket", "chat", "contact", "info",
	"intranet", "extranet", "corp", "corporate", "office",
	"mail1", "mail2", "smtp1", "smtp2", "pop3", "imap",
	"exchange", "owa", "outlook", "calendar", "meet",
	"video", "voice", "phone", "sip", "voip",
	"web", "web1", "web2", "www1", "www2", "www3",
	"proxy", "gateway", "router", "firewall", "fw",
	"lb", "loadbalancer", "balance", "cluster",
	"node", "node1", "node2", "server", "srv",
	"host", "host1", "host2", "vm", "virtual",
	"container", "docker", "k8s", "kubernetes",
	"s3", "storage", "archive", "vault",
	"ssl", "tls", "wireguard",
	"openvpn", "rdp", "ssh", "telnet",
	"sftp", "ftps", "tftp", "nfs", "smb",
	"cifs", "webdav", "dav", "caldav", "carddav",
	"ldap", "ad", "dc", "dc1", "dc2",
	"pki", "ca", "cert", "certs", "certificate",
}

func LoadWordlist(customPath string) []string {
	if customPath != "" {
		words, err := loadFromFile(customPath)
		if err != nil {
			log.Warn().Err(err).Str("path", customPath).Msg("Failed to load custom wordlist, falling back")
		} else {
			log.Info().Int("count", len(words)).Str("path", customPath).Msg("Loaded custom wordlist")
			return words
		}
	}

	for _, path := range seclistsPaths {
		words, err := loadFromFile(path)
		if err == nil {
			log.Info().Int("count", len(words)).Str("path", path).Msg("Loaded SecLists wordlist")
			return words
		}
	}

	log.Info().Int("count", len(builtinWordlist)).Msg("Using built-in wordlist")
	return builtinWordlist
}

func loadFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var words []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		word := scanner.Text()
		if word != "" {
			words = append(words, word)
		}
	}
	return words, scanner.Err()
}
