// Policy CLI commands: validate, test, diff, activate, init.
package cli

import (
	"fmt"
	"log"
	"os"
	"strings"

	"offense.dev/raid/core/canonical"
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
	path := "raid-policy.yaml"
	if len(args) >= 1 && args[0] != "" {
		path = args[0]
	}
	if err := os.WriteFile(path, []byte(starterPolicy), 0o644); err != nil {
		log.Fatalf("raid: %v", err)
	}
	fmt.Printf("wrote starter policy to %s (deny by default; edit and run: raid policy activate %s)\n", path, path)
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
