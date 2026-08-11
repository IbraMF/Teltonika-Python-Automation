import json
import pathlib
import time
from typing import Any

import requests


class Wireguard:
    base_url: str
    headers: dict[str, str]

    def __init__(self, ip: str, headers: dict[str, str]):
        self.base_url = f"http://{ip}/api/wireguard"
        self.headers = headers

    def get_config(self) -> dict[str, Any]:
        r = requests.get(f"{self.base_url}/config", headers=self.headers, verify=False)
        r.raise_for_status()
        return r.json()

    def print_config(self) -> None:
        conf = self.get_config()
        print("-" * 20 + "\033[1mWireguard Config\033[0m" + "-" * 20)
        print(json.dumps(conf, indent=2))

    def create_instance(self, data_dict: dict[str, str]) -> None:
        print("-" * 20 + "\033[1mCreating Wireguard Instance\033[0m" + "-" * 20)

        data = {"data": data_dict}
        r = requests.post(f"{self.base_url}/config", headers=self.headers, json=data, verify=False)
        print(r.text)
        r.raise_for_status()

    def add_peer(
        self,
        name: str,
        peer_id: str,
        peer_public_key: str,
        peer_allowed_ips: list[str],
        route_allowed: str = "1",
        keepalive: str = "25",
    ) -> None:
        print("-" * 20 + "\033[1mAdding Peer Wireguard\033[0m" + "-" * 20)
        peer_data = {
            "data": {
                "id": peer_id,
                "public_key": peer_public_key,
                "allowed_ips": peer_allowed_ips,
                "route_allowed_ips": route_allowed,
                "persistent_keepalive": keepalive,
            }
        }

        r = requests.post(f"{self.base_url}/{name}/peers/config", headers=self.headers, json=peer_data, verify=False)
        print(r.text)
        r.raise_for_status()


class OpenVPN:
    base_url: str
    headers: dict[str, str]

    def __init__(self, ip: str, headers: dict[str, str]):
        self.base_url = f"http://{ip}/api/openvpn"
        self.headers = headers

    def get_config(self) -> dict[str, Any]:
        r = requests.get(f"{self.base_url}/config", headers=self.headers, verify=False)
        r.raise_for_status()
        return r.json()

    def print_config(self) -> None:
        conf = self.get_config()
        print("-" * 20 + "\033[1mOpenVPN Config\033[0m" + "-" * 20)
        print(json.dumps(conf, indent=2))

    def _get_new_section(self) -> str:
        config = self.get_config()
        count = 0
        for instance in config["data"]:
            count = max(count, int(instance["id"].strip("inst")))
        return f"inst{count + 1}"

    def upload_certificate(self, section: str, file: pathlib.Path | str, option: str) -> str:
        r = requests.post(
            f"{self.base_url}/config/{section}",
            headers={"Authorization": f"{self.headers['Authorization']}"},
            files={"option": option, "file": open(file, "rb")},
            verify=False,
        )
        r.raise_for_status()
        print(r.json())
        return r.json()["data"]["path"]

    def create_instance(
        self, data_dict: dict[str, str], common_name: str = None, cert_dir: pathlib.Path = None
    ) -> None:
        print("-" * 20 + "\033[1mCreating OpenVPN Instance\033[0m" + "-" * 20)

        retries = 3
        for attempt in range(1, retries + 1):  # TODO convertir request with attempts para ConnectionError en funcion
            try:
                new_section = self._get_new_section()
                if common_name and cert_dir:
                    ca_path = cert_dir / "ca.crt"
                    cert_path = cert_dir / f"{common_name}.crt"
                    key_path = cert_dir / f"{common_name}.key"

                    data_dict["ca"] = self.upload_certificate(new_section, ca_path, "ca")
                    data_dict["key"] = self.upload_certificate(new_section, key_path, "key")
                    data_dict["cert"] = self.upload_certificate(new_section, cert_path, "cert")

                if data_dict.get("tls_security", None):
                    ta_path = cert_dir / "ta.key"
                    data_dict["tls_auth"] = self.upload_certificate(new_section, ta_path, "tls_auth")

                data = {"data": data_dict}

                r = requests.post(f"{self.base_url}/config", headers=self.headers, json=data, verify=False)
                print(r.text)
                if r.json()["success"] is True:
                    return
                r.raise_for_status()
            except requests.exceptions.ConnectionError as e:
                print(f"Error de conexión (intento {attempt}/{retries}): {e}")
                if attempt == retries:
                    print("No quedan intentos")
                    raise  # si ya no queda reintento → relanzar error
                time.sleep(3)  # esperar antes del siguiente intento
            except Exception as e:
                print(f"Otro error inesperado: {e}")
                raise
