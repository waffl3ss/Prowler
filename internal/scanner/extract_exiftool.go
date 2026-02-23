package scanner

import (
	"encoding/json"
	"os/exec"

	"github.com/rs/zerolog/log"
)

var exiftoolAvailable *bool

func HasExiftool() bool {
	if exiftoolAvailable != nil {
		return *exiftoolAvailable
	}
	_, err := exec.LookPath("exiftool")
	avail := err == nil
	exiftoolAvailable = &avail
	if avail {
		log.Info().Msg("exiftool detected")
	} else {
		log.Info().Msg("exiftool not found - using native extraction only")
	}
	return avail
}

func ExtractWithExiftool(filepath string) map[string]string {
	meta := make(map[string]string)

	if !HasExiftool() {
		return meta
	}

	cmd := exec.Command("exiftool", "-j", filepath)
	output, err := cmd.Output()
	if err != nil {
		log.Debug().Err(err).Str("file", filepath).Msg("exiftool failed")
		return meta
	}

	var results []map[string]interface{}
	if err := json.Unmarshal(output, &results); err != nil {
		log.Debug().Err(err).Msg("exiftool JSON parse failed")
		return meta
	}

	if len(results) == 0 {
		return meta
	}

	data := results[0]
	fields := []string{
		"Author", "Creator", "Producer", "Title", "Subject",
		"Company", "Manager", "Keywords", "Comments",
		"LastModifiedBy", "Software", "CreatorTool",
		"CreateDate", "ModifyDate", "MetadataDate",
		"SourceModified", "RevisionNumber", "TotalEditTime",
		"Pages", "PageCount", "Slides", "Words", "Characters",
		"Application", "Template", "HyperlinkBase",
	}

	for _, f := range fields {
		if v, ok := data[f]; ok {
			if s, ok := v.(string); ok && s != "" {
				meta[f] = s
			} else if v != nil {
				meta[f] = jsonString(v)
			}
		}
	}

	return meta
}

func jsonString(v interface{}) string {
	b, _ := json.Marshal(v)
	s := string(b)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	return s
}
