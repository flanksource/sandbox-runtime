# sandbox-runtime

Go SDK and CLI for running shell commands inside an OS-level sandbox with network and filesystem restrictions.

Uses [bubblewrap](https://github.com/containers/bubblewrap) on Linux and `sandbox-exec` on macOS.

Go port of [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime) (TypeScript).

## SDK

```go
import "github.com/flanksource/sandbox-runtime/sandbox"
```

```go
sb, err := sandbox.New(sandbox.Config{
    AllowedDomains: []string{"github.com", "*.github.com", "*.docker.io"},
    AllowWrite:     []string{"/tmp", "/home/user/project"},
    DenyRead:       []string{"/etc/shadow"},
}, sandbox.WithAskCallback(func(p sandbox.AskParams) bool {
    // Optional fallback decision for hosts not matched by allowed/denied rules.
    return p.Host == "registry.internal.local" && p.Port == 443
}))
if err != nil {
    log.Fatal(err)
}
defer sb.Close()

// Get an *exec.Cmd — full control over stdin/stdout/stderr
cmd, err := sb.Command(ctx, "curl -s https://github.com")
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
| `sandbox.New(cfg, opts...)`   | Start proxy servers, validate platform dependencies     |
| `sandbox.WithAskCallback(fn)` | Dynamic network allow/deny callback for unmatched hosts |
| `sb.Command(ctx, cmd)`        | Returns `*exec.Cmd` wrapped with bwrap/sandbox-exec     |
| `sb.Close()`                  | Tear down proxies and clean up                          |

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

Options:
  -d, --debug                enable debug logging
  -s, --settings <path>      path to config file (default: ~/.srt-settings.json)
  -c <command>               run command string directly
  --control-fd <fd>          read config updates from fd (JSON lines)
  -h, --help                 show help
```

### CLI Config

The CLI uses a JSON config file (see `config.json` for an example):

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
