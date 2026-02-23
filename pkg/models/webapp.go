package models

type WebApp struct {
	URL          string `json:"url"`
	StatusCode   int    `json:"status_code"`
	Title        string `json:"title"`
	Technology   string `json:"technology"`
	Server       string `json:"server"`
	XPoweredBy   string `json:"x_powered_by,omitempty"`
	RequiresAuth bool   `json:"requires_auth"`
}

type Phase4Results struct {
	Apps []WebApp `json:"apps"`
}
