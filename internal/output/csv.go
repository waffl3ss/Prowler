package output

import (
	"encoding/csv"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
)

type CSVWriter struct {
	outputDir string
}

func NewCSVWriter(outputDir string) *CSVWriter {
	return &CSVWriter{outputDir: outputDir}
}

func (w *CSVWriter) Write(filename string, headers []string, rows [][]string) error {
	path := filepath.Join(w.outputDir, filename)

	f, err := os.Create(path)
	if err != nil {
		log.Error().Err(err).Str("file", path).Msg("Failed to create CSV file")
		return err
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	if err := writer.Write(headers); err != nil {
		return err
	}

	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}
