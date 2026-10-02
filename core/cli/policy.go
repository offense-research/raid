// Policy CLI commands: validate, test, diff, activate, init.
package cli

import (
	"fmt"
	"log"
	"os"
	"strings"

	"offense.dev/raid/core/canonical"
	"offense.dev/raid/core/nlpolicy"
	"offense.dev/raid/core/policy"
	"offense.dev/raid/pkg/raidclient"
)

func cmdPolicy(args []string) int {
	if len(args) < 1 {
		log.Printf("raid: policy requires a subcommand")
		return 2
	}
	switch args[0] {
	case "validate":
		return policyValidate(args[1:])
	case "test":
		return policyTest(args[1:])
	case "diff":
		return policyDiff(args[1:])
	case "activate":
		return policyActivate(args[1:])
	case "init":
		return policyInit(args[1:])
	case "presets":
		return policyPresets(args[1:])
	case "from-language":
		return policyFromLanguage(args[1:])
	}
	log.Printf("raid: unknown policy subcommand %q", args[0])
	return 2
}

// starterPolicy is the generated starter bundle (acceptance: <1 minute to a
// starter policy).
const starterPolicy = `apiVersion: offense.dev/raid/v1alpha1
kind: PolicyBundle
metadata:
  name: surge-default
  revision: 1
defaults:
  effect: deny
rules:
  - id: deny-missing-policy
    description: Default deny until rules are added
    match:
      providers: [surge]
    when: "true"
    effect: deny
`

func policyInit(args []string) int {
	path := ""
	preset := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--preset", "-p":
			if i+1 < len(args) {
				preset = args[i+1]
				i++
			}
		default:
			if len(a) > 0 && a[0] != '-' && path == "" {
				path = a
			}
		}
	}
	if preset != "" {
		data, ok := policy.Preset(preset)
		if !ok {
			log.Printf("raid: unknown preset %q (see: raid policy presets)", preset)
			return 2
		}
		if path == "" {
			path = preset + ".policy.yaml"
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			log.Fatalf("raid: %v", err)
		}
		fmt.Printf("wrote %s preset to %s\n", preset, path)
		fmt.Printf("activate with: raid policy activate %s   (or boot raidd with --policy-preset %s)\n", path, preset)
		return 0
	}
	if path == "" {
		path = "raid-policy.yaml"
	}
	if err := os.WriteFile(path, []byte(starterPolicy), 0o644); err != nil {
		log.Fatalf("raid: %v", err)
	}
	fmt.Printf("wrote starter policy to %s (deny by default; edit and run: raid policy activate %s)\n", path, path)
	return 0
}

// policyPresets lists the embedded onboarding presets.
func policyPresets(args []string) int {
	_ = args
	for _, name := range policy.PresetNames() {
		fmt.Printf("%-14s %s\n", name, policy.PresetDescription(name))
	}
	return 0
}

// policyFromLanguage drafts a policy bundle from a natural-language statement
// using an OpenRouter LLM. The draft is only trusted after it passes the
// deterministic load + compile gate, and is emitted/activated only then.
func policyFromLanguage(args []string) int {
	var statement, key, model, outPath string
	activate := false
	interactive := false
	for i, a := range args {
		switch a {
		case "--statement", "-s":
			if i + 1 < len(args) {
				statement = args[i+1]
			}
		case "--key":
			if i + 1 < len(args) {
				key = args[i+1]
			}
		case "--model":
			if i + 1 < len(args) {
				model = args[i+1]
			}
		case "--out":
			if i + 1 < len(args) {
				outPath = args[i+1]
			}
		case "--activate":
			activate = true
		case "--interactive", "-i":
			interactive = true
		}
	}
	if interactive {
		if outPath != "" {
			log.Printf("raid: --interactive does not take --out; save from inside the TUI")
			return 2
		}
		return nlpolicy.Run()
	}
	if statement == "" {
		log.Printf("raid: policy from-language --statement <natural language permissions> [--key KEY] [--model M] [--out FILE] [--activate]")
		return 2
	}
	if key == "" {
		key = os.Getenv(nlpolicy.KeyEnv)
	}
	if key == "" {
		log.Printf("raid: an OpenRouter API key is required (set %s or pass --key)", nlpolicy.KeyEnv)
		return 2
	}
	yamlText, terr := nlpolicy.Translate(nil, nlpolicy.TranslateOptions{ApiKey: key, Model: model}, statement)
	if terr != nil {
		log.Printf("raid: could not draft policy from language: %v", terr.Error())
		return 1
	}
	// deterministic gate: an LLM draft is never authority until it validates
	schema, lerr := policy.LoadBundle([]byte(yamlText), "language")
	if lerr != nil {
		log.Printf("raid: drafted policy did not validate: %v", lerr.Error())
		return 1
	}
	compiled, cerr := policy.CompileBundle(schema, policy.CompileOptions{})
	if cerr != nil {
		log.Printf("raid: drafted policy did not compile: %v", cerr.Error())
		return 1
	}
	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(yamlText), 0o644); err != nil {
			log.Fatalf("raid: %v", err)
		}
		fmt.Printf("wrote drafted policy to %s (%d rules)\n", outPath, len(compiled.Rules()))
	}
	if activate {
		client := raidclient.NewClient(socketPath())
		resp, err := client.Post("/v1/policies/activate", yamlText, approverOf(), nil)
		resp = checkErr(resp, err)
		if resp.Status != 200 {
			fmt.Println(resp.BodyString())
			return 1
		}
		fmt.Println(resp.BodyString())
		return 0
	}
	if outPath == "" && !activate {
		fmt.Println(yamlText)
	}
	return 0
}

func policyValidate(paths []string) int {
	if len(paths) != 1 {
		log.Printf("raid: policy validate <file>")
		return 2
	}
	path := paths[0]
	schema, lerr := policy.LoadBundleFile(path)
	if lerr != nil {
		log.Printf("raid: invalid policy: %v", lerr.Error())
		return 1
	}
	b, cerr := policy.CompileBundle(schema, policy.CompileOptions{})
	if cerr != nil {
		log.Printf("raid: policy does not compile: %v", cerr.Error())
		return 1
	}
	fmt.Printf("policy %s: valid (%d rules, %d tests)\n", b.ID(), len(b.Rules()), len(b.Tests()))
	return 0
}

func policyTest(paths []string) int {
	if len(paths) != 1 {
		log.Printf("raid: policy test <file>")
		return 2
	}
	path := paths[0]
	schema, lerr := policy.LoadBundleFile(path)
	if lerr != nil {
		log.Printf("raid: invalid policy: %v", lerr.Error())
		return 1
	}
	dir := dirname(path)
	loader := func(input string) (*canonical.ActionRequest, error) {
		data, rerr := os.ReadFile(dir + "/" + input)
		if rerr != nil {
			return nil, rerr
		}
		return canonical.DecodeRequest(data)
	}
	b, cerr := policy.CompileBundle(schema, policy.CompileOptions{RequestLoader: loader})
	if cerr != nil {
		log.Printf("raid: policy tests failed activation: %v", cerr.Error())
		return 1
	}
	sb := fmt.Sprintf("all %d embedded tests passed", len(b.Tests()))
	fmt.Println(sb)
	return 0
}

func policyDiff(paths []string) int {
	if len(paths) != 2 {
		log.Printf("raid: policy diff <old> <new>")
		return 2
	}
	oldS, lerr := policy.LoadBundleFile(paths[0])
	if lerr != nil {
		log.Printf("raid: old policy invalid: %v", lerr.Error())
		return 1
	}
	newS, lerr := policy.LoadBundleFile(paths[1])
	if lerr != nil {
		log.Printf("raid: new policy invalid: %v", lerr.Error())
		return 1
	}
	rep := policy.DiffPolicy(oldS, newS)
	fmt.Println(rep.String())
	return 0
}

func policyActivate(paths []string) int {
	if len(paths) != 1 {
		log.Printf("raid: policy activate <file>")
		return 2
	}
	data := readFileOrDie(paths[0])
	client := raidclient.NewClient(socketPath())
	resp, err := client.Post("/v1/policies/activate", string(data), approverOf(), nil)
	resp = checkErr(resp, err)
	if resp.Status != 200 {
		fmt.Println(resp.BodyString())
		return 1
	}
	fmt.Println(resp.BodyString())
	return 0
}

func dirname(path string) string {
	i := strings.LastIndexByte(path, '/')
	if i < 0 {
		return "."
	}
	if i == 0 {
		return "/"
	}
	return path[:i]
}
