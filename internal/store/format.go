package store

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// Format describes how a credential's content is encoded.
type Format string

// Supported formats.
const (
	FormatTXT  Format = "txt"
	FormatJSON Format = "json"
	FormatYAML Format = "yaml"
	FormatTOML Format = "toml"
	FormatEnv  Format = "env"
	FormatPEM  Format = "pem"
)

// Formats lists the supported formats in display order.
var Formats = []Format{FormatTXT, FormatJSON, FormatYAML, FormatTOML, FormatEnv, FormatPEM}

var contentTypes = map[Format]string{
	FormatTXT:  "text/plain; charset=utf-8",
	FormatJSON: "application/json",
	FormatYAML: "application/yaml",
	FormatTOML: "application/toml",
	FormatEnv:  "text/plain; charset=utf-8",
	FormatPEM:  "application/x-pem-file",
}

// ContentType returns the MIME type used when serving content of this format.
func (f Format) ContentType() string {
	if ct, ok := contentTypes[f]; ok {
		return ct
	}
	return "application/octet-stream"
}

// Valid reports whether f is a supported format.
func (f Format) Valid() bool {
	_, ok := contentTypes[f]
	return ok
}

// Validate checks that content is well-formed for the format.
func (f Format) Validate(content string) error {
	var v any
	switch f {
	case FormatTXT, FormatEnv:
		return nil
	case FormatJSON:
		if err := json.Unmarshal([]byte(content), &v); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
	case FormatYAML:
		if err := yaml.Unmarshal([]byte(content), &v); err != nil {
			return fmt.Errorf("invalid YAML: %w", err)
		}
	case FormatTOML:
		if _, err := toml.Decode(content, &v); err != nil {
			return fmt.Errorf("invalid TOML: %w", err)
		}
	case FormatPEM:
		if block, _ := pem.Decode(bytes.TrimSpace([]byte(content))); block == nil {
			return fmt.Errorf("invalid PEM: no PEM block found")
		}
	default:
		return fmt.Errorf("unknown format %q", f)
	}
	return nil
}
