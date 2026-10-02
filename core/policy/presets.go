// Embedded policy presets for one-command onboarding.
//
// Presets are complete, opinionated bundles an individual engineer can drop in
// with `raid policy init --preset <name>` (or `raidd --solo`). They are
// embedded so the single binary is self-contained; `raid policy validate`
// still runs the identical strict decode + compile gate as a file on disk.
package policy

import (
	"embed"
	"sort"
	"strings"
)

//go:embed presets/*.yaml
var presetFS embed.FS

// presetDescriptions are one-line summaries shown by `raid policy presets`.
var presetDescriptions = map[string]string{
	"solo-dev-safe": "Guardrails + confirmations for one engineer driving an agent (deny-first).",
	"review-only":   "Read-only agent: inspect the world, change nothing.",
	"ci-agent":      "Build/test/write in dev, confirm in prod, never rewrite history.",
}

// PresetNames returns the available preset names, sorted.
func PresetNames() []string {
	entries, err := presetFS.ReadDir("presets")
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".yaml")
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// PresetDescription returns the human summary for a preset ("" when unknown).
func PresetDescription(name string) string {
	return presetDescriptions[name]
}

// Preset returns the YAML bytes of a preset bundle.
func Preset(name string) ([]byte, bool) {
	if name == "" {
		return nil, false
	}
	data, err := presetFS.ReadFile("presets/" + name + ".yaml")
	if err != nil {
		return nil, false
	}
	return data, true
}

// LoadPreset parses an embedded preset through the strict loader.
func LoadPreset(name string) (*BundleSchema, *LoadError) {
	data, ok := Preset(name)
	if !ok {
		return nil, &LoadError{msg: "unknown policy preset " + name}
	}
	return LoadBundle(data, "preset:"+name)
}

// CompilePreset loads and compiles an embedded preset.
func CompilePreset(name string) (*CompiledBundle, *CompileError, *LoadError) {
	schema, lerr := LoadPreset(name)
	if lerr != nil {
		return nil, nil, lerr
	}
	b, cerr := CompileBundle(schema, CompileOptions{})
	if cerr != nil {
		return nil, cerr, nil
	}
	return b, nil, nil
}
