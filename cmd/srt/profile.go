package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/flanksource/sandbox-runtime/internal/srt"
	"gopkg.in/yaml.v3"
)

func runProfile(args []string) int {
	if len(args) == 0 {
		printProfileHelp()
		return 0
	}

	switch args[0] {
	case "list":
		return profileList()
	case "show":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: srt profile show <preset-name>")
			return 1
		}
		return profileShow(args[1])
	case "resolve":
		return profileResolve()
	default:
		fmt.Fprintf(os.Stderr, "Unknown profile subcommand: %s\n", args[0])
		printProfileHelp()
		return 1
	}
}

func profileList() int {
	for _, name := range srt.ListPresets() {
		fmt.Println(name)
	}
	return 0
}

func profileShow(name string) int {
	p, err := srt.GetPreset(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	data, err := yaml.Marshal(p)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	fmt.Print(string(data))
	return 0
}

func profileResolve() int {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	cfg, err := srt.LoadProfiles(cwd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	if cfg == nil {
		fmt.Fprintln(os.Stderr, "No .sandbox.yaml found")
		return 1
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	fmt.Println(string(data))
	return 0
}

func dedup(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

func printProfileHelp() {
	fmt.Println("Usage: srt profile <subcommand>")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  list              List available preset names")
	fmt.Println("  show <name>       Show expanded preset (network, fs, env, passthroughEnv)")
	fmt.Println("  resolve           Show final merged config for cwd as JSON")
	fmt.Println("  init              Detect project type, suggest starter .sandbox.yaml")
	fmt.Println()
	fmt.Println("Init flags:")
	fmt.Println("  --ai-model <model>  Use AI to generate config from Claude Code history")
	fmt.Println("  --since <duration>  History window (default: 168h / 7 days)")
	fmt.Println("  --all               Scan all projects, not just cwd")
	fmt.Println("  --save              Write .sandbox.yaml without prompting")
	fmt.Println()
	fmt.Println("Each preset configures network domains, filesystem write paths, explicit env")
	fmt.Println("vars, and passthroughEnv (host env var names forwarded into the sandbox).")
}
