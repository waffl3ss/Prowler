package util

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type RDAPNetwork struct {
	Handle    string   `json:"handle"`
	Name      string   `json:"name"`
	CIDRs     []CIDR   `json:"cidr0_cidrs"`
	StartAddr string   `json:"startAddress"`
	EndAddr   string   `json:"endAddress"`
}

type CIDR struct {
	V4Prefix string `json:"v4prefix"`
	V6Prefix string `json:"v6prefix"`
	Length   int    `json:"length"`
}

func LookupNetblock(ip string) ([]string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("https://rdap.arin.net/registry/ip/%s", ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("RDAP returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var network RDAPNetwork
	if err := json.Unmarshal(body, &network); err != nil {
		return nil, err
	}

	var cidrs []string
	for _, c := range network.CIDRs {
		if c.V4Prefix != "" {
			cidrs = append(cidrs, fmt.Sprintf("%s/%d", c.V4Prefix, c.Length))
		}
		if c.V6Prefix != "" {
			cidrs = append(cidrs, fmt.Sprintf("%s/%d", c.V6Prefix, c.Length))
		}
	}

	if len(cidrs) == 0 && network.StartAddr != "" && network.EndAddr != "" {
		cidrs = append(cidrs, fmt.Sprintf("%s - %s", network.StartAddr, network.EndAddr))
	}

	return cidrs, nil
}
