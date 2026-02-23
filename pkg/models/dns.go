package models

type DNSRecord struct {
	Domain     string `json:"domain"`
	RecordType string `json:"record_type"`
	Value      string `json:"value"`
	TTL        uint32 `json:"ttl"`
}

type ZoneTransferResult struct {
	Domain      string            `json:"domain"`
	Nameservers map[string]string `json:"nameservers"`
}

type Phase2Results struct {
	Results []ZoneTransferResult `json:"results"`
}
