config = {
    # SIM unlock task:
    # POST /api/modems/{modem_id}/actions/sim_unlock
    # Body is generated from this PIN as: {"data": {"pin": "..."}}
    "sim_pin": "",
    # Used for login before changes. Not sent directly to an API endpoint.
    "current": {
        "ip": "",
        "username": "admin",
        "password": "",
    },
    # Used for login after changes, root password change, and LAN task.
    # LAN task builds: PUT /api/interfaces/config/lan
    "expected": {
        "ip": "",
        "mask": "",
        "password": "",
    },
    # OpenVPN task:
    # POST /api/openvpn/config
    # "config" is the raw request body. common_name/cert_dir/backup_dir are used for certificate upload and backup naming.
    "ovpn": {
        "common_name": "",
        "cert_dir": "",
        "backup_dir": "",
        "config": {"data": {}},
    },
    # WireGuard task:
    # config -> POST /api/wireguard/config
    # peers[interface_id] -> POST /api/wireguard/{interface_id}/peers/config
    "wg": {
        "config": {"data": {}},
        "peers": {
            # "wg0": [
            #     {"data": {}},
            # ],
        },
    },
    # Users task:
    # POST /api/users/config
    "new_users": [
        # {"data": {}},
    ],
    # User groups permissions task:
    # PUT /api/users/groups/config
    # Use GET /api/users/groups/config to copy the group ids and available permission fields.
    "user_groups": {
        "data": [
            # {
            #     "id": "admin",
            #     "read": [],
            #     "write": [],
            # },
        ]
    },
    # Access control task:
    # ssh -> PUT /api/access_control/ssh/config
    # cli -> PUT /api/access_control/cli/config
    # webui -> PUT /api/access_control/webui/config/{id}
    # webui remote access fields are "http_wan_access" and "https_wan_access".
    "access_control": {
        "ssh": {"data": []},
        "cli": {"data": []},
        "webui": {"data": []},
    },
    # Port forwarding task:
    # POST /api/firewall/port_forwards/config
    "port_forwarding": [
        # {"data": {}},
    ],
    # Auto reboot task:
    # PUT /api/auto_reboot/ping_wget/config
    "auto_reboot": {"data": []},
    # SMS utilities task:
    # GET /api/sms_utilities/rules/config, then PUT /api/sms_utilities/rules/config
    # The function maps these SMS text names to the real rule ids returned by GET.
    "sms_utilities": {
        "enable_list": [
            # "all",
            # "reboot",
            # "vpnon",
            # "vpnoff",
        ]
    },
    # NTP task:
    # client -> PUT /api/date_time/ntp/client/config
    # server -> PUT /api/date_time/ntp/server/config
    # timeservers -> PUT /api/date_time/ntp/time_servers/config
    "ntp": {
        "client": {"data": []},
        "server": {"data": []},
        "timeservers": {"data": []},
        # DELETE /api/date_time/ntp/time_servers/config
        "timeservers_delete": {"data": []},
    },
    # Wireless Wi-Fi task:
    # PUT /api/wireless/interfaces/config
    "wifi": {"data": []},
    # Custom APN task:
    # PUT /api/interfaces/config
    "apn": {"data": []},
    # SIM cards task:
    # PUT /api/sim_cards/config
    "sim_cards": {"data": []},
    # Disable WAN interfaces task:
    # PUT /api/interfaces/config
    "wan_interfaces": {"data": []},
    # DHCP IPv4 range task:
    # PUT /api/dhcp/servers/ipv4/config
    "dhcp_ipv4": {"data": []},
    # RMS disable task:
    # PUT /api/rms/config
    "rms": {"data": []},
    # System task:
    # PUT /api/system/config
    "system": {"data": []},
}
