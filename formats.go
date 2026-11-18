package main

import (
	"encoding/json"
	"fmt"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// Formats connus : le contenu est validé à l'enregistrement et le format
// détermine le Content-Type renvoyé par l'endpoint /raw.
var formats = map[string]string{
	"txt":  "text/plain; charset=utf-8",
	"json": "application/json",
	"yaml": "application/yaml",
	"toml": "application/toml",
	"env":  "text/plain; charset=utf-8",
	"pem":  "application/x-pem-file",
}

var formatOrder = []string{"txt", "json", "yaml", "toml", "env", "pem"}

func ValidateFormat(format, content string) error {
	if _, ok := formats[format]; !ok {
		return fmt.Errorf("format inconnu %q", format)
	}
	var v any
	switch format {
	case "json":
		if err := json.Unmarshal([]byte(content), &v); err != nil {
			return fmt.Errorf("JSON invalide : %v", err)
		}
	case "yaml":
		if err := yaml.Unmarshal([]byte(content), &v); err != nil {
			return fmt.Errorf("YAML invalide : %v", err)
		}
	case "toml":
		if _, err := toml.Decode(content, &v); err != nil {
			return fmt.Errorf("TOML invalide : %v", err)
		}
	}
	return nil
}
