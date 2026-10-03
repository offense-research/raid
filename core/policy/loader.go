// Strict policy bundle loading.
package policy

import (
	"io"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

// LoadError describes a bundle loading or validation failure.
type LoadError struct {
	msg string
}

func (e *LoadError) Error() string { return e.msg }

// LoadSources reads a policy document from disk.
type LoadSources struct {
	Path string
}

// LoadBundle strictly decodes a policy document.
//
// Failure modes: unreadable file, multi-document stream, unknown top-level
// fields, missing apiVersion/kind, and schema mismatches. Unknown fields
// nested inside known objects are also rejected by the strict decoder.
func LoadBundle(data []byte, sourcePath string) (*BundleSchema, *LoadError) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	var schema BundleSchema
	err := dec.Decode(&schema)
	if err != nil {
		if err == io.EOF {
			return nil, &LoadError{msg: "empty policy document"}
		}
		return nil, &LoadError{msg: "policy YAML error: " + err.Error()}
	}
	// reject trailing documents
	var second BundleSchema
	err2 := dec.Decode(&second)
	if err2 == nil {
		return nil, &LoadError{msg: "policy document must contain exactly one YAML document"}
	}
	if err2 != io.EOF {
		return nil, &LoadError{msg: "policy YAML stream error: " + err2.Error()}
	}
	if schema.ApiVersion != "" && schema.ApiVersion != ApiVersion {
		return nil, &LoadError{msg: "unsupported apiVersion " + schema.ApiVersion}
	}
	if schema.ApiVersion == "" {
		return nil, &LoadError{msg: "missing required field apiVersion"}
	}
	if schema.Kind != "" && schema.Kind != Kind {
		return nil, &LoadError{msg: "unsupported kind " + schema.Kind}
	}
	if schema.Kind == "" {
		return nil, &LoadError{msg: "missing required field kind"}
	}
	if schema.Metadata == nil {
		return nil, &LoadError{msg: "missing required field metadata"}
	}
	if schema.Metadata.Name == "" {
		return nil, &LoadError{msg: "missing required field metadata.name"}
	}
	if schema.Defaults == nil {
		return nil, &LoadError{msg: "missing required field defaults"}
	}
	if schema.Defaults.Effect != "allow" && schema.Defaults.Effect != "deny" {
		return nil, &LoadError{msg: "defaults.effect must be allow or deny"}
	}
	if len(schema.Rules) == 0 {
		return nil, &LoadError{msg: "bundle must declare at least one rule"}
	}
	return &schema, nil
}

// LoadBundleFile reads and strictly decodes a bundle from disk.
func LoadBundleFile(path string) (*BundleSchema, *LoadError) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &LoadError{msg: "cannot read " + path + ": " + err.Error()}
	}
	return LoadBundle(data, path)
}

func fmtMsg(parts ...string) string {
	var sb strings.Builder
	for _, p := range parts {
		sb.WriteString(p)
	}
	return sb.String()
}
