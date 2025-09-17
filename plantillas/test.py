config = {
    
    "sim_pin": 1234,
    "current": {
        "ip": "192.168.1.1",
        "password": "Admin123",
        "username": "admin",
    },
    "expected": {
        "ip": "192.168.3.1",
        "mask": "255.255.255.0",
        "password": "Admin12345.",
    },
    "ovpn": {
        "name": "CentroControl",
        "protocol": "udp",
        "port": "10194",
        "ip": "10.1.0.0",
        "mask": "255.255.255.0",
        "server": "server.es",
        "cipher": "AES-256-GCM",
        "common_name": "RUT901", 
        "cert_dir": "C:\\Users\\ibrah\\Downloads\\cert\\test",  # Public & Private certs with common name here
        "backup_dir": "C:\\Users\\ibrah\\Downloads\\cert\\test\\backup",  # Needs to exist
    },
    "wg": {
        "name": "wg0",
        "public_key": "fx06GdodtdC2rrUA+0PrSn2z+/YVS3yioFNaoRnCUEQ=", 
        "private_key": "YKPNakJznOhkE9+HpC0kDFE1oN2lTSU/+D8YpGloAFA=", 
        "port": "51820", 
        "ip": ["172.16.0.1/32"],
        "peers": {
            "PC1": {
                "public_key": "vA9zIhhvvSfLbDAwfObMJzvqrrSeiYmgOIXRUkC8chI=",
                "ip": ["172.16.0.0/24"],
                "route_allowed": "1",
                "keepalive": "25"
            }
        },
    },
    "new_users": {
        "mock_user": {
            "password": "Mock123.",
            "type": "admin"
        }
    },
    "access_control":{
        "ssh": {
            "enabled": False,
            "wan_access": False
        },
        "cli": {
            "enabled": False,
            "wan_access": False
        }
    },
    "port_forwarding": {
        "PLC": {
            "proto": ["tcp"],
            "source": "openvpn",
            "source_port": "1112",
            "dest_port": "1102",
            "dest_ip": "192.168.3.10"
        },
        "Camera Web": {
            "proto": ["udp", "tcp"],
            "source": "openvpn",
            "source_port": "3043",
            "dest_port": "3043",
            "dest_ip": "192.168.3.20"
        },
        "Camera App": {
            "proto": ["udp", "tcp"],
            "source": "openvpn",
            "source_port": "3090",
            "dest_port": "3090",
            "dest_ip": "192.168.3.20"
        },
    },
    "auto_reboot": {
        "enable": True,
        "retry": "3",
        "timeout": "10",
    },
    "sms_utilities": {
        "enable_list": [
            "all"  # Or list SMS text: "reboot", "status", "sshoff", "monitoring_status"
        ]
    },
    "ntp": {
        "timezone": "Europe/Madrid",
        "client_enable": True,
        "force_servers": True,
        "interval": "7200",
        "operator_sync": False,
        "server_enable": True,
        "timeservers": {
            '1': '10.1.0.1'
        }
    },
}
