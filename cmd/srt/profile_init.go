package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/flanksource/captain/pkg/ai"
	"github.com/flanksource/captain/pkg/claude"
	"github.com/flanksource/captain/pkg/cli"
	"github.com/flanksource/sandbox-runtime/internal/srt"
	"github.com/flanksource/sandbox-runtime/internal/srt/presets"
	"gopkg.in/yaml.v3"
)

type profileInitOptions struct {
	aiModel string
	since   time.Duration
	all     bool
	save    bool
}

func parseProfileInitArgs(args []string) (profileInitOptions, error) {
	opts := profileInitOptions{since: 7 * 24 * time.Hour}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--ai-model":
			i++
			if i >= len(args) {
				return opts, fmt.Errorf("missing value for --ai-model")
			}
			opts.aiModel = args[i]
		case "--since":
			i++
			if i >= len(args) {
				return opts, fmt.Errorf("missing value for --since")
			}
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return opts, fmt.Errorf("invalid --since value: %w", err)
			}
			opts.since = d
		case "--all":
			opts.all = true
		case "--save":
			opts.save = true
		default:
			return opts, fmt.Errorf("unknown flag: %s", args[i])
		}
	}
	return opts, nil
}

func profileInit(args []string) int {
	opts, err := parseProfileInitArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}

	if opts.aiModel == "" {
		return profileInitBasic()
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}

	history, err := aggregateHistory(cwd, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error aggregating history:", err)
		return 1
	}

	prompt, err := buildAIPrompt(history)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error building prompt:", err)
		return 1
	}

	yamlOutput, err := callAI(opts.aiModel, prompt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error calling AI:", err)
		return 1
	}

	var profile srt.Profile
	if err := yaml.Unmarshal([]byte(yamlOutput), &profile); err != nil {
		fmt.Fprintln(os.Stderr, "Error: AI returned invalid YAML:", err)
		fmt.Fprintln(os.Stderr, "Raw output:")
		fmt.Fprintln(os.Stderr, yamlOutput)
		return 1
	}

	cleanYAML, err := yaml.Marshal(&profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}

	fmt.Println(string(cleanYAML))

	if opts.save {
		return writeProfile(cwd, cleanYAML)
	}

	fmt.Fprint(os.Stderr, "Write to .sandbox.yaml? [y/N] ")
	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(answer)) == "y" {
		return writeProfile(cwd, cleanYAML)
	}
	return 0
}

func writeProfile(cwd string, yamlData []byte) int {
	path := cwd + "/.sandbox.yaml"
	if err := os.WriteFile(path, yamlData, 0644); err != nil {
		fmt.Fprintln(os.Stderr, "Error writing .sandbox.yaml:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "Wrote %s\n", path)
	return 0
}

func aggregateHistory(cwd string, opts profileInitOptions) (*cli.SRTConfig, error) {
	since := time.Now().Add(-opts.since)
	filter := claude.Filter{Since: &since}
	parseResult, err := claude.ParseHistory(cwd, opts.all, filter)
	if err != nil {
		return nil, fmt.Errorf("parsing history: %w", err)
	}

	config := cli.SRTConfig{
		Network:    cli.SRTNetwork{AllowedDomains: make([]string, 0)},
		Filesystem: cli.SRTFilesystem{AllowWrite: []string{".", "/tmp"}},
		Environment: cli.SRTEnvironment{
			Passthrough: make([]string, 0),
		},
	}

	domains := make(map[string]bool)
	writeDirs := map[string]bool{".": true, "/tmp": true}
	projectRoot := claude.FindProjectRoot(cwd)

	for _, tu := range parseResult.ToolUses {
		if tu.ProjectRoot == "" {
			tu.ProjectRoot = projectRoot
		}
		analysis := cli.AnalyzeToolUse(tu, projectRoot)
		for _, d := range analysis.Domains {
			domains[d] = true
		}
		for _, p := range analysis.WritePaths {
			writeDirs[p] = true
		}
	}

	for d := range domains {
		config.Network.AllowedDomains = append(config.Network.AllowedDomains, d)
	}
	for p := range writeDirs {
		config.Filesystem.AllowWrite = append(config.Filesystem.AllowWrite, p)
	}

	return &config, nil
}

func buildAIPrompt(history *cli.SRTConfig) (string, error) {
	presetNames := srt.ListPresets()

	var presetSummaries []string
	for _, name := range presetNames {
		raw, err := presets.Get(name)
		if err != nil {
			continue
		}
		presetSummaries = append(presetSummaries, fmt.Sprintf("--- %s ---\n%s", name, string(raw)))
	}

	var sb strings.Builder
	sb.WriteString("Given the following usage history from Claude Code sessions:\n\n")

	sb.WriteString("Domains accessed:\n")
	for _, d := range history.Network.AllowedDomains {
		sb.WriteString("  - " + d + "\n")
	}

	sb.WriteString("\nPaths written:\n")
	for _, p := range history.Filesystem.AllowWrite {
		sb.WriteString("  - " + p + "\n")
	}

	sb.WriteString("\nEnvironment variables used:\n")
	for _, e := range history.Environment.Passthrough {
		sb.WriteString("  - " + e + "\n")
	}

	sb.WriteString("\nAvailable presets and their contents:\n\n")
	sb.WriteString(strings.Join(presetSummaries, "\n\n"))

	sb.WriteString(`

Generate a .sandbox.yaml that:
1. Uses preset names in the "allow:" field wherever a preset covers the observed usage
2. Adds custom network.allowedDomains only for domains NOT covered by any preset
3. Adds custom filesystem.allowWrite only for paths NOT covered by any preset
4. Adds passthroughEnv for env vars NOT covered by any preset
5. Keep it minimal — prefer presets over raw config
6. Always include "git" in allow if .git was detected
`)
	return sb.String(), nil
}

func callAI(model, prompt string) (string, error) {
	provider, err := ai.NewProvider(ai.Config{Model: model})
	if err != nil {
		return "", fmt.Errorf("creating AI provider: %w", err)
	}

	resp, err := provider.Execute(context.Background(), ai.Request{
		SystemPrompt: `You generate .sandbox.yaml files for the srt sandbox runtime.
Output ONLY valid YAML matching the Profile schema. No markdown fences, no explanation.
The Profile schema has these top-level fields: allow, network, filesystem, env, passthroughEnv, ignoreViolations, enableWeakerNestedSandbox, enableWeakerNetworkIsolation, allowPty.`,
		Prompt: prompt,
	})
	if err != nil {
		return "", fmt.Errorf("AI request: %w", err)
	}

	return strings.TrimSpace(resp.Text), nil
}

func profileInitBasic() int {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}

	var detected []string
	markers := map[string]string{
		"go.mod":           "golang",
		"package.json":     "npm",
		"Cargo.toml":       "rust",
		"pyproject.toml":   "python",
		"requirements.txt": "python",
		"Dockerfile":       "docker",
		".git":             "git",
	}
	for file, preset := range markers {
		if _, err := os.Stat(cwd + "/" + file); err == nil {
			detected = append(detected, preset)
		}
	}

	detected = dedup(detected)
	if len(detected) == 0 {
		fmt.Println("# No ecosystems detected. Add presets manually:")
		fmt.Println("allow: []")
	} else {
		fmt.Printf("# Detected: %s\n", strings.Join(detected, ", "))
		fmt.Printf("allow: [%s]\n", strings.Join(detected, ", "))
	}
	fmt.Println()
	fmt.Println("# Tip: use --ai-model <model> for AI-powered init based on Claude Code history")
	return 0
}
