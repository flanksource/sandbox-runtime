package presets

import (
	"embed"
	"fmt"
	"sort"
	"strings"
)

//go:embed *.yaml
var presetsFS embed.FS

func Get(name string) ([]byte, error) {
	data, err := presetsFS.ReadFile(name + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("unknown preset %q", name)
	}
	return data, nil
}

func List() []string {
	entries, err := presetsFS.ReadDir(".")
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, strings.TrimSuffix(e.Name(), ".yaml"))
		}
	}
	sort.Strings(names)
	return names
}
