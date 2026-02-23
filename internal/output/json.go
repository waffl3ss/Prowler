package output

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
)

type JSONWriter struct {
	outputDir string
}

func NewJSONWriter(outputDir string) *JSONWriter {
	return &JSONWriter{outputDir: outputDir}
}

func (w *JSONWriter) Write(filename string, data interface{}) error {
	path := filepath.Join(w.outputDir, filename)

	f, err := os.Create(path)
	if err != nil {
		log.Error().Err(err).Str("file", path).Msg("Failed to create JSON file")
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		log.Error().Err(err).Str("file", path).Msg("Failed to write JSON")
		return err
	}

	return nil
}
