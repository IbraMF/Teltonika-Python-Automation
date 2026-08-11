# Teltonika Python Automation

Interactive Python CLI for applying repeatable configuration templates to Teltonika routers through the device HTTP API.

The app is intended for repetitive router setup work: select a template, choose the tasks to run, confirm the execution, and let the script apply the selected configuration in order.

This project was originally built for personal use and reflects my own Teltonika setup workflow. Anyone is free to take it, modify it, and adapt the code to add the functionality they prefer for their own devices or deployment process.

## Current functionality

- Select configuration templates from `plantillas/*.py`.
- Interactive task picker with grouped selections:
  - `Basic offline`: LAN, firmware update, root password, users.
  - `Others`: VPNs, firewall, access control, SIM, Wi-Fi, system, backup, and other services.
- Retry, skip, or stop when an individual task fails.
- Automatic re-login after LAN IP or root password changes.
- Waits for the router to come back online after disruptive operations such as LAN changes, firmware upgrades, and backup restore.

Supported tasks:

- LAN IP and netmask change.
- Firmware update through FOTA.
- WireGuard instance creation and peer creation.
- OpenVPN instance creation with certificate upload.
- Root password change.
- User creation.
- User group permission updates.
- SSH, CLI, and WebUI access-control configuration.
- Firewall port-forward creation or update by rule name.
- Auto reboot configuration.
- SMS utilities rule enable/disable.
- NTP client, server, time-server, and time-server delete configuration.
- Wireless interface configuration.
- Custom APN/interface configuration.
- SIM card configuration.
- WAN interface configuration.
- DHCP IPv4 server range configuration.
- RMS configuration.
- System configuration.
- SIM unlock by PIN.
- Backup download and backup restore.

## Requirements

- Python 3.10+ recommended.
- Network access to the target Teltonika router.
- Router HTTP API enabled and reachable.
- Valid router admin credentials.

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the CLI:

```bash
python main.py
```

Flow:

1. Select a template from the `plantillas` folder.
2. Select one or more tasks.
3. Confirm execution.
4. If a task fails, choose whether to retry it, skip it, or stop the run.

Keyboard controls:

- Use `↑` / `↓` or `k` / `j` to move.
- Use `Space` to select tasks.
- Use `Enter` to confirm.
- Use `Ctrl+C` to cancel.

## Templates

Templates are Python files in `plantillas/`. Each template must expose a top-level `config` dictionary.

Start from:

```text
plantillas/default.py
```

Minimum required sections:

```python
config = {
    "current": {
        "ip": "192.168.1.1",
        "username": "admin",
        "password": "current-password",
    },
    "expected": {
        "ip": "192.168.10.1",
        "mask": "255.255.255.0",
        "password": "new-password",
    },
}
```

Most tasks are skipped automatically when their matching template section is empty. For example, if `wg`, `ovpn`, `wifi`, or `backup.path` are empty, those tasks will not run even if selected.

Do not commit real production templates containing router credentials, SIM PINs, certificates, or customer network data.

## Optional executable build

`pyinstaller` is included in `requirements.txt`. A simple one-file Windows build can be created with:

```bash
pyinstaller --onefile main.py
```

The app loads templates from the folder next to the executable, so copy `plantillas/` next to the generated `.exe` before running it.

## Project structure

```text
.
├── main.py                 # CLI entry point
├── task_cli.py             # Template loading, task selection, execution flow
├── other.py                # Router API operations for non-VPN tasks
├── vpn.py                  # OpenVPN and WireGuard API helpers
├── plantillas/
│   └── default.py          # Example template structure
├── requirements.txt
└── README.md
```

## Notes

- The script uses the router HTTP API and disables TLS warnings because current requests are made with `verify=False`.
- Firmware updates and backup restore can reboot or temporarily disconnect the router.
- LAN and password changes affect the IP/password used by later tasks, so the script handles those transitions internally.
