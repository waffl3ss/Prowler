package scanner

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/rs/zerolog/log"
)

// Dublin Core metadata from docProps/core.xml
type coreProperties struct {
	XMLName        xml.Name `xml:"coreProperties"`
	Creator        string   `xml:"creator"`
	Title          string   `xml:"title"`
	Subject        string   `xml:"subject"`
	Description    string   `xml:"description"`
	Keywords       string   `xml:"keywords"`
	LastModifiedBy string   `xml:"lastModifiedBy"`
	Revision       string   `xml:"revision"`
	Created        string   `xml:"created"`
	Modified       string   `xml:"modified"`
}

// Extended properties from docProps/app.xml
type appProperties struct {
	XMLName     xml.Name `xml:"Properties"`
	Application string   `xml:"Application"`
	AppVersion  string   `xml:"AppVersion"`
	Template    string   `xml:"Template"`
	Company     string   `xml:"Company"`
	Manager     string   `xml:"Manager"`
	Pages       int      `xml:"Pages"`
	Words       int      `xml:"Words"`
	Slides      int      `xml:"Slides"`
}

func ExtractOOXMLMetadata(filepath string) map[string]string {
	meta := make(map[string]string)

	r, err := zip.OpenReader(filepath)
	if err != nil {
		log.Debug().Err(err).Str("file", filepath).Msg("Cannot open as ZIP")
		return meta
	}
	defer r.Close()

	for _, f := range r.File {
		switch strings.ToLower(f.Name) {
		case "docprops/core.xml":
			extractCoreProps(f, meta)
		case "docprops/app.xml":
			extractAppProps(f, meta)
		}
	}

	return meta
}

func extractCoreProps(f *zip.File, meta map[string]string) {
	rc, err := f.Open()
	if err != nil {
		return
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return
	}

	var core coreProperties
	if err := xml.Unmarshal(data, &core); err != nil {
		log.Debug().Err(err).Msg("Failed to parse core.xml")
		return
	}

	if core.Creator != "" {
		meta["Creator"] = core.Creator
	}
	if core.Title != "" {
		meta["Title"] = core.Title
	}
	if core.Subject != "" {
		meta["Subject"] = core.Subject
	}
	if core.Description != "" {
		meta["Description"] = core.Description
	}
	if core.Keywords != "" {
		meta["Keywords"] = core.Keywords
	}
	if core.LastModifiedBy != "" {
		meta["LastModifiedBy"] = core.LastModifiedBy
	}
	if core.Revision != "" {
		meta["Revision"] = core.Revision
	}
	if core.Created != "" {
		meta["Created"] = core.Created
	}
	if core.Modified != "" {
		meta["Modified"] = core.Modified
	}
}

func extractAppProps(f *zip.File, meta map[string]string) {
	rc, err := f.Open()
	if err != nil {
		return
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return
	}

	var app appProperties
	if err := xml.Unmarshal(data, &app); err != nil {
		log.Debug().Err(err).Msg("Failed to parse app.xml")
		return
	}

	if app.Application != "" {
		meta["Application"] = app.Application
	}
	if app.AppVersion != "" {
		meta["AppVersion"] = app.AppVersion
	}
	if app.Template != "" {
		meta["Template"] = app.Template
	}
	if app.Company != "" {
		meta["Company"] = app.Company
	}
	if app.Manager != "" {
		meta["Manager"] = app.Manager
	}
	if app.Pages > 0 {
		meta["Pages"] = fmt.Sprintf("%d", app.Pages)
	}
	if app.Slides > 0 {
		meta["Slides"] = fmt.Sprintf("%d", app.Slides)
	}
}
