# zblock

Domain-blocking focus tool for macOS that pairs a command-line interface with a privileged daemon to enforce PF firewall rules during timed focus sessions.

## Installation

### Using a Release Tarball

1. Download the archive matching your platform/architecture from the project releases (named `zblock-<version>-<OS>-<ARCH>.tar.gz`).
2. Extract the binaries:
   ```sh
   tar -xzvf zblock-<version>-<OS>-<ARCH>.tar.gz
   ```
3. Move the executables into your `$PATH` (for example):
   ```sh
   sudo mv zblock /usr/local/bin/
   sudo mv zblockd /usr/local/libexec/
   ```

## Usage

### Initialize the Environment

```sh
sudo zblock init
```

### Manage Domain Groups

Add domains to the default group:

```sh
zblock add x.com news.ycombinator.com
```

Add domains to a custom group:

```sh
zblock add --group social reddit.com instagram.com
```

List configured domains:

```sh
zblock list
zblock list --group social --json
```

### Start a Focus Session

Start a timed block for every group:

```sh
zblock start --for 45m
```

Target a single group and enable DNS lockdown:

```sh
zblock start --for 90m --group social --dns-lockdown
```

During a session, the daemon resolves configured domains, maintains PF tables for IPv4/IPv6 targets, and (optionally) blocks DNS and known DoH egress.

### Check Status

```sh
zblock status
zblock status --json
```

Shows whether a focus session is active, the remaining time, targeted groups, and counts of resolved addresses.

### Uninstall

```sh
sudo zblock uninstall
```

Stops and disables the launchd service, clears PF anchors/tables, removes installed binaries, and deletes runtime state. Pass `--purge` to remove the user config as well. You cannot uninstall while a focus session is active.

## Troubleshooting

- Ensure PF is available (`sudo pfctl -s info`). The daemon logs to `/var/log/zblock/daemon.log`.
- Use `zblock list` to confirm domains were added; `zblock status` after `start` should report resolved targets.
- If network access still succeeds during a session, check that launchd is running the daemon (`sudo launchctl print system/com.zblock.daemon`).
