package models

type SMTPCommandStatus string

const (
	SMTPAllowed        SMTPCommandStatus = "ALLOWED"
	SMTPProhibited     SMTPCommandStatus = "PROHIBITED"
	SMTPNotImplemented SMTPCommandStatus = "NOT_IMPLEMENTED"
	SMTPError          SMTPCommandStatus = "ERROR"
)

type SMTPResult struct {
	MXHost string            `json:"mx_host"`
	VRFY   SMTPCommandStatus `json:"vrfy"`
	EXPN   SMTPCommandStatus `json:"expn"`
	RCPT   SMTPCommandStatus `json:"rcpt"`
}

type Phase3Results struct {
	MXHosts []string     `json:"mx_hosts"`
	Results []SMTPResult `json:"results"`
}
