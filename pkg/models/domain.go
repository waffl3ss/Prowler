package models

type DomainInfo struct {
	Domain    string   `json:"domain"`
	IPs       []string `json:"ips"`
	Registrar string   `json:"registrar"`
	Netblocks []string `json:"netblocks"`
	Source    string   `json:"source"`
}

type Phase1Results struct {
	Domains         map[string]*DomainInfo `json:"domains"`
	TotalDiscovered int                    `json:"total_discovered"`
	CTDomains       []string               `json:"ct_domains"`
	DNSRecords      []DNSRecord            `json:"dns_records"`
}
