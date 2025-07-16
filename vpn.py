import requests, json, pathlib

class Wireguard:
    def __init__(self, ip: str, headers: dict):
        self.base_url = f"http://{ip}/api/wireguard"
        self.headers = headers

    def get_config(self) -> dict:
        r = requests.get(f"{self.base_url}/config", headers=self.headers, verify=False)
        r.raise_for_status()
        return r.json()
    
    def print_config(self) -> None:
        conf = self.get_config()
        print("-"*20+"\033[1mWireguard Config\033[0m"+"-"*20)
        print(json.dumps(conf, indent=2))

    def create_instance(self, name: str, private_key: str, public_key: str, listen_port: str, allowed_ips: list[str], peer_id: str, peer_public_key: str, peer_allowed_ips: list[str]) -> None:
        print("-"*20+"\033[1mCreating Wireguard Instance\033[0m"+"-"*20)

        data = {"data": {
            "enabled": "1",
            "id": name,
            "private_key": private_key,
            "public_key": public_key,
            ".type": "interface",
            "listen_port": listen_port,
            "addresses": allowed_ips
        }}
        r = requests.post(f"{self.base_url}/config", headers=self.headers, json=data, verify=False)
        print(r.text)
        r.raise_for_status()

        peer_data = {"data":{
            "id": peer_id,
            "public_key": peer_public_key,
            "allowed_ips": peer_allowed_ips,
            "route_allowed_ips": "1",
            "persistent_keepalive": "25"

        }}

        r = requests.post(f"{self.base_url}/{name}/peers/config", headers=self.headers, json=peer_data, verify=False)

class OpenVPN:
    def __init__(self, ip: str, headers: dict):
        self.base_url = f"http://{ip}/api/openvpn"
        self.headers = headers

    def get_config(self) -> dict:
        r = requests.get(f"{self.base_url}/config", headers=self.headers, verify=False)
        r.raise_for_status()
        return r.json()
    
    def print_config(self) -> None:
        conf = self.get_config()
        print("-"*20+"\033[1mOpenVPN Config\033[0m"+"-"*20)
        print(json.dumps(conf, indent=2))

    def _get_new_section(self) -> str:
        config = self.get_config()
        count = 0
        for instance in config["data"]:
            count = max(count, int(instance["id"].strip("inst")))
        return f"inst{count+1}"

    def upload_certificate(self, section: str, file: str, option: str) -> str:
        r = requests.post(f"{self.base_url}/config/{section}", headers={"Authorization": f"{self.headers["Authorization"]}"}, files={"option": option, "file": open(file, "rb")}, verify=False)
        r.raise_for_status()
        print(r.json())
        return r.json()["data"]["path"]

    def create_instance(self, name: str, port: str, ca_path: str, cert_path: str, key_path: str, remote_host: str, ip: str, mask: str) -> None:
        print("-"*20+"\033[1mCreating OpenVPN Instance\033[0m"+"-"*20)

        new_section = self._get_new_section()
        ca_path = self.upload_certificate(new_section, ca_path, "ca")
        cert_path = self.upload_certificate(new_section, cert_path, "cert")
        key_path = self.upload_certificate(new_section, key_path, "key")

        data = {"data": {
            "enable": "1",
            "name": name,
            "type": "client",
            "proto": "udp",
            "auth_mode": 
            "tls",
            "topology" :"subnet",
            "port": port,
            "remote": [remote_host],
            "network_ip": ip,
            "network_mask": mask,
            "comp_lzo": "yes",
            "upload_files": "1", 
            "ca": ca_path,
            "cert": cert_path,
            "key": key_path,
            "cipher": "AES-256-GCM",
            "cipher_custom": ["aes-256-gcm"],
        }}
        r = requests.post(f"{self.base_url}/config", headers=self.headers, json=data, verify=False)
        print(r.text)
        r.raise_for_status()
    
