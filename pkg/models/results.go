package models

import "time"

type ReconResults struct {
	Target    string         `json:"target"`
	StartedAt time.Time     `json:"started_at"`
	EndedAt   time.Time     `json:"ended_at"`
	Phase1    *Phase1Results `json:"phase1,omitempty"`
	Phase2    *Phase2Results `json:"phase2,omitempty"`
	Phase3    *Phase3Results `json:"phase3,omitempty"`
	Phase4    *Phase4Results `json:"phase4,omitempty"`
	Phase5    *Phase5Results `json:"phase5,omitempty"`
}

type ScanResults struct {
	Target    string         `json:"target"`
	StartedAt time.Time     `json:"started_at"`
	EndedAt   time.Time     `json:"ended_at"`
	Phase6    *Phase6Results `json:"phase6,omitempty"`
}

type FullResults struct {
	Target    string        `json:"target"`
	StartedAt time.Time    `json:"started_at"`
	EndedAt   time.Time    `json:"ended_at"`
	Recon     *ReconResults `json:"recon,omitempty"`
	Scan      *ScanResults  `json:"scan,omitempty"`
}
