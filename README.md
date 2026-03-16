# sandbox-runtime

Go SDK and CLI for running shell commands inside an OS-level sandbox with network and filesystem restrictions.

Uses [bubblewrap](https://github.com/containers/bubblewrap) on Linux and `sandbox-exec` on macOS.

Go port of [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime) (TypeScript).

## SDK

```go
import "github.com/flanksource/sandbox-runtime/sandbox"
```

```go
cfg := sandbox.Config{
    AllowedDomains: []string{"github.com", "*.github.com", "*.docker.io"},
    AllowWrite:     []string{"/tmp", "/home/user/project"},
    DenyRead:       []string{"/etc/shadow"},
}

if !sandbox.IsSupported(cfg) {
    log.Fatal("sandbox runtime is not supported in this environment")
}

sb, err := sandbox.New(ctx, cfg, sandbox.WithAskCallback(func(p sandbox.AskParams) bool {
    // Optional fallback decision for hosts not matched by allowed/denied rules.
    return p.Host == "registry.internal.local" && p.Port == 443
}))
if err != nil {
    log.Fatal(err)
}
defer sb.Close(ctx)

// Get an *exec.Cmd — full control over stdin/stdout/stderr
cmd, err := sb.Command(ctx, "curl", "-s", "https://github.com")
if err != nil {
    log.Fatal(err)
}
cmd.Stdout = os.Stdout
cmd.Stderr = os.Stderr
cmd.Run()
```

### API

|                               |                                                         |
| ----------------------------- | ------------------------------------------------------- |
| `sandbox.IsSupported(cfg)`    | Preflight check for platform + config-aware dependencies |
| `sandbox.New(ctx, cfg, opts...)` | Start proxy servers, validate platform dependencies |
| `sandbox.WithAskCallback(fn)` | Dynamic network allow/deny callback for unmatched hosts |
| `sb.Command(ctx, name, args...)` | Returns `*exec.Cmd` wrapped with bwrap/sandbox-exec |
| `sb.Close(ctx)`               | Tear down proxies and clean up                          |

### Config

```go
type Config struct {
    // Network policy
    AllowedDomains      []string
    DeniedDomains       []string
    AllowUnixSockets    []string
    AllowAllUnixSockets bool
    AllowLocalBinding   bool
    HTTPProxyPort       *int
    SocksProxyPort      *int
    MitmProxy           *MitmProxyConfig

    // Filesystem policy
    AllowWrite     []string
    DenyWrite      []string
    DenyRead       []string
    AllowGitConfig bool

    // Environment
    Env            map[string]string  // explicit key=value vars injected into sandbox
    PassthroughEnv []string           // host env var names passed through if set

    // Runtime behavior
    IgnoreViolations             map[string][]string
    EnableWeakerNestedSandbox    bool
    EnableWeakerNetworkIsolation bool
    AllowPty                     bool

    // Linux mandatory deny tuning
    MandatoryDenySearchDepth int
    Ripgrep                  *RipgrepConfig
    Seccomp                  *SeccompConfig

    Debug bool
}
```

## CLI

```bash
make build
./bin/srt --help
```

```
srt - Run commands in a sandbox with network and filesystem restrictions

Usage:
  srt [options] [command ...]
  srt -c <command>

Subcommands:
  profile <subcommand>              Manage sandbox profiles and presets
  test-sandbox <fixture-paths...>   Run fixture-based sandbox tests

Options:
  -d, --debug                enable debug logging
  -s, --settings <path>      path to config file (default: ~/.srt-settings.json)
  -c <command>               run command string directly
  --control-fd <fd>          read config updates from fd (JSON lines)
  -h, --help                 show help
```

### Profiles and Presets

Instead of writing a full JSON config, you can use `.sandbox.yaml` profile files with built-in presets.

#### Full `.sandbox.yaml` Reference

```yaml
# ─── Presets ──────────────────────────────────────────────────────────
# Include built-in presets by name. Each preset adds network domains,
# filesystem write paths, env vars, and passthroughEnv for its ecosystem.
#
# Available: golang, npm, python, rust, docker, git, ssh,
#            aws, gcp, azure, homebrew, ide, shell
allow:
  - golang
  - git

# ─── Network ─────────────────────────────────────────────────────────
network:
  # Domains the sandbox can reach (merged with preset domains)
  allowedDomains:
    - custom-registry.example.com
    - "*.internal.corp"            # wildcard subdomains

  # Domains explicitly blocked (checked before allowedDomains)
  deniedDomains:
    - evil.example.com

  # Allow specific unix sockets inside the sandbox
  allowUnixSockets:
    - /var/run/docker.sock

  # Allow ALL unix sockets (overrides allowUnixSockets)
  allowAllUnixSockets: false

  # Allow binding to localhost ports (for local dev servers)
  allowLocalBinding: false

  # Use external proxy instead of built-in (optional)
  # httpProxyPort: 8080
  # socksProxyPort: 1080

  # Route matching domains through a MITM proxy unix socket (optional)
  # mitmProxy:
  #   socketPath: /tmp/mitmproxy.sock
  #   domains: ["api.example.com"]

# ─── Filesystem ──────────────────────────────────────────────────────
filesystem:
  # Paths writable inside the sandbox (merged with preset paths)
  # Supports ~ expansion and $ENV_VAR substitution
  allowWrite:
    - .                            # current working directory
    - /tmp
    - $HOME/.cache

  # Paths denied for reading (blocked even though fs is readable by default)
  denyRead:
    - $HOME/.ssh
    - $HOME/.aws/credentials

  # Paths denied for writing within allowWrite paths
  denyWrite:
    - .env
    - "**/.env.local"

  # Allow reading/writing .git/config (blocked by default)
  allowGitConfig: false

# ─── Environment ─────────────────────────────────────────────────────
# Explicit key=value env vars injected into sandbox (overrides passthrough)
env:
  GONOSUMCHECK: "*"
  NODE_TLS_REJECT_UNAUTHORIZED: "0"

# Host env var names to pass through into sandbox if set
# (merged with preset passthroughEnv and built-in defaults like
#  TERM, HOME, USER, SHELL, PATH, LANG, EDITOR, XDG_*)
passthroughEnv:
  - MY_CUSTOM_TOKEN
  - DATABASE_URL

# ─── Violation Handling ──────────────────────────────────────────────
# Suppress sandbox violation logs for specific commands
ignoreViolations:
  curl:                            # command name
    - network                      # violation category to ignore
  git:
    - network
    - filesystem

# ─── Runtime Behavior ────────────────────────────────────────────────
# Allow pseudo-terminal allocation (needed for interactive commands)
allowPty: false

# Weaken nested sandbox restrictions (needed for docker-in-sandbox)
enableWeakerNestedSandbox: false

# Allow trustd.agent mach-lookup on macOS (needed for Go TLS verification)
enableWeakerNetworkIsolation: false
```

#### Minimal Example

```yaml
# .sandbox.yaml — typical Go project
allow: [golang, git]
```

Use `srt profile show <name>` to inspect what any preset includes.

```bash
srt profile list               # list available presets
srt profile show golang        # show preset details
srt profile resolve            # show final merged config for cwd
srt profile init               # detect project type, suggest .sandbox.yaml
```

### Environment Variables

Sandboxed commands run in a clean environment. Environment variables are injected in three layers (later layers override earlier ones):

1. **Default passthrough** — a safe set of host env vars (`TERM`, `HOME`, `USER`, `SHELL`, `PATH`, `LANG`, `EDITOR`, `XDG_*`, etc.) are passed through automatically if set on the host.

2. **Preset/profile passthrough** — presets declare additional env var names to pass through. For example, the `golang` preset passes through `GOPATH`, `GOMODCACHE`, `GOROOT`, `GOPROXY`, `GOPRIVATE`, and `GOBIN`. You can also add custom names via `passthroughEnv` in `.sandbox.yaml`.

3. **Explicit env** — `env` key-value pairs (from presets or `.sandbox.yaml`) are injected directly and override any passthrough value for the same key.

### CLI Config (JSON)

The CLI also supports a JSON config file (`~/.srt-settings.json`):

```json
{
  "network": {
    "allowedDomains": ["github.com", "*.github.com"],
    "deniedDomains": [],
    "allowLocalBinding": true,
    "allowAllUnixSockets": true
  },
  "filesystem": {
    "denyRead": [],
    "allowWrite": ["/tmp"],
    "denyWrite": []
  },
  "passthroughEnv": ["MY_CUSTOM_VAR"],
  "env": {
    "GONOSUMCHECK": "*"
  }
}
```

## Dependencies

**Linux:** `bwrap` (bubblewrap), `socat`, `rg` (ripgrep)

**macOS:** `sandbox-exec` (ships with macOS), `rg` (ripgrep)

## Architecture

### Network

On Linux, `bwrap --unshare-net` creates an isolated network namespace where the sandboxed process cannot reach the host's `localhost`.
To bridge this gap, `socat` tunnels proxy traffic across the namespace boundary using Unix sockets.
Host-side socat processes listen on Unix sockets (passed into the sandbox via `--bind`) and forward to the HTTP/SOCKS proxies on TCP localhost.
Inside the sandbox, additional socat processes listen on TCP ports (3128/1080) and forward to those Unix sockets.

### Filesystem

Filesystem isolation works by creating a new mount namespace where the root filesystem is bind-mounted read-only using `--ro-bind / /`, then selectively overlaying writable paths with `--bind` mounts.
Specific files or directories can be blocked from read access by mounting an empty tmpfs (`--tmpfs`) over directories or binding them to `/dev/null`, while writes are restricted by remounting allowed paths as read-only (`--ro-bind`).

On macOS, the same policies are enforced via Seatbelt profiles (`sandbox-exec`) since the BSD kernel lacks bind mounts, using explicit allow/deny rules for file-read and file-write operations.

## Development

```bash
make test      # run tests
make build     # build CLI binary to ./bin/srt
make check     # fmt + vet + test
```
