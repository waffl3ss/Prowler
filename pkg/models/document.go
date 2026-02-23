package models

import "time"

type DocumentURL struct {
	URL      string `json:"url"`
	Engine   string `json:"engine"`
	FileType string `json:"file_type"`
}

type DownloadResult struct {
	URL       string `json:"url"`
	Success   bool   `json:"success"`
	LocalPath string `json:"local_path,omitempty"`
	FileHash  string `json:"file_hash,omitempty"`
	Error     string `json:"error,omitempty"`
}

type DocumentMetadata struct {
	SourceURL   string            `json:"source_url"`
	LocalPath   string            `json:"local_path"`
	FileHash    string            `json:"file_hash"`
	FileType    string            `json:"file_type"`
	Metadata    map[string]string `json:"metadata"`
	ExtractedAt time.Time         `json:"extracted_at"`
}

type Phase6Results struct {
	DocumentURLs    []DocumentURL      `json:"document_urls"`
	Downloads       []DownloadResult   `json:"downloads"`
	Metadata        []DocumentMetadata `json:"metadata"`
	UniqueUsernames []string           `json:"unique_usernames"`
	UniqueSoftware  []string           `json:"unique_software"`
}
