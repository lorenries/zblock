# zblock

Domain-blocking focus tool for macOS that pairs a command-line interface with a privileged daemon to enforce PF firewall rules during timed focus sessions.

## Installation

### Quick Install (recommended)

Run the install script to download the latest notarized release, place `zblock`/`zblockd` under `~/.zblock/bin`, and print PATH instructions:

```sh
curl -fsSL https://raw.githubusercontent.com/lorenries/zblock/main/scripts/install.sh | bash
```

- Use `ZBLOCK_VERSION=v0.x.y` to pin a specific tag.
- Set `ZBLOCK_INSTALL_DIR` or `ZBLOCK_BIN_DIR` to customize the destination.
- After installation, ensure `~/.zblock/bin` is on your `PATH` (the script tells you what to add).

### Manual Installation

1. Download the archive matching your platform/architecture from the releases page (`zblock-<version>-<OS>-<ARCH>.zip`).
2. Extract the binaries:
   ```sh
   unzip zblock-<version>-<OS>-<ARCH>.zip
   ```
3. Move the executables into your preferred locations, for example:
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
