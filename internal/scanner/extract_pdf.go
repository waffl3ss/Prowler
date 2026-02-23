package scanner

import (
	"fmt"
	"os"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/rs/zerolog/log"
)

func ExtractPDFMetadata(filepath string) map[string]string {
	meta := make(map[string]string)

	f, err := os.Open(filepath)
	if err != nil {
		log.Debug().Err(err).Str("file", filepath).Msg("Cannot open PDF")
		return meta
	}
	defer f.Close()

	ctx, err := api.ReadAndValidate(f, model.NewDefaultConfiguration())
	if err != nil {
		log.Debug().Err(err).Str("file", filepath).Msg("Cannot read PDF")
		return meta
	}

	if ctx.XRefTable == nil {
		return meta
	}

	xrt := ctx.XRefTable

	if xrt.Author != "" {
		meta["Author"] = xrt.Author
	}
	if xrt.Creator != "" {
		meta["Creator"] = xrt.Creator
	}
	if xrt.Producer != "" {
		meta["Producer"] = xrt.Producer
	}
	if xrt.Title != "" {
		meta["Title"] = xrt.Title
	}
	if xrt.Subject != "" {
		meta["Subject"] = xrt.Subject
	}
	if xrt.CreationDate != "" {
		meta["CreationDate"] = xrt.CreationDate
	}
	if xrt.ModDate != "" {
		meta["ModDate"] = xrt.ModDate
	}

	meta["Pages"] = fmt.Sprintf("%d", xrt.PageCount)

	return meta
}
