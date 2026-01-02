# ns

`ns` is a prettier, more usable alternative to `netstat` with:

- A fast table mode for scripting and quick checks
- An interactive TUI mode (default) with live refresh and instant filtering
- PID + process-name resolution for sockets
- JSON output for tooling

## Install

### From source

```bash
cargo install --path .
```

### Build a release binary

```bash
cargo build --release
```

The binary will be at:

- Windows: `target\release\ns.exe`
- Linux/macOS: `target/release/ns`

## Usage

### Interactive mode (default)

Run with no args:

```bash
ns
```

#### Keys

- `q` quit
- `/` focus filter input
- `esc` reset filter + focus list
- `r` refresh now
- `t` toggle TCP, `u` toggle UDP
- `4` toggle IPv4, `6` toggle IPv6
- `l` toggle listening-only
- `s` cycle sort column, `d` toggle descending
- `c` clear filter

#### Filter language

Type free text to match across proto/local/remote/state/pid/process. You can also use power tokens:

- `port:443` or `p:443`
- `pid:1234`
- `proc:chrome` / `process:chrome`
- `state:listen` / `state:established`
- `tcp`, `udp`, `listen`

Examples:

- `proc:chrome port:443`
- `tcp state:estab`
- `listen`

### Non-interactive (CLI) mode

Show help:

```bash
ns --help
```

Show listening TCP sockets:

```bash
ns --listen --tcp
```

Filter by port:

```bash
ns --port 443
```

Filter by PID or process name:

```bash
ns --pid 1234
ns --process chrome
```

Sort:

```bash
ns --sort process
ns --sort local-port --desc
```

JSON:

```bash
ns --json
```

## Output notes

- UDP sockets don’t have a TCP-like connection state, so state is shown as `—`.
- Some platforms/OS configs may require elevated privileges to see owning PIDs/processes for all sockets.

## Development

```bash
cargo fmt
cargo clippy -- -D warnings
cargo test
```
