package output

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

type TXTWriter struct {
	outputDir string
}

func NewTXTWriter(outputDir string) *TXTWriter {
	return &TXTWriter{outputDir: outputDir}
}

func (w *TXTWriter) WriteLines(filename string, lines []string) error {
	path := filepath.Join(w.outputDir, filename)

	f, err := os.Create(path)
	if err != nil {
		log.Error().Err(err).Str("file", path).Msg("Failed to create TXT file")
		return err
	}
	defer f.Close()

	_, err = f.WriteString(strings.Join(lines, "\n") + "\n")
	return err
}
