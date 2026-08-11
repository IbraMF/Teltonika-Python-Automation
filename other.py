import json
import pathlib
import sys

import requests
from requests.models import Response


def login(ip: str, user: str, password: str, is_wait_for_router: bool = False):
    if is_wait_for_router:
        _ = wait_for_router(ip, skip_first_try=True)

    url = f"http://{ip}/api/login"
    login_data = {"username": user, "password": password}
    headers = {"Content-type": "application/json"}

    login = requests.post(url, json=login_data, headers=headers, verify=False)
    login_out = json.loads(login.text)

    if login_out["success"]:
        token = login_out["data"]["token"]
        print("Login Correcto")
        headers["Authorization"] = f"Bearer {token}"
        return headers
    else:
        raise Exception(f"Error en el login: {login_out}")


def change_lan(ip: str, header: dict[str, str], new_lan_ip: str, mask: str, gateway: str = "") -> str:
    print("-" * 20 + "\033[1mChanging LAN IP/MASK\033[0m" + "-" * 20)

    base_url = f"http://{ip}/api/interfaces/config/lan"

    data = {"data": {"ipaddr": new_lan_ip, "netmask": mask}}

    if gateway != "":
        data["gateway"] = gateway

    r = requests.put(base_url, headers=header, json=data, verify=False)
    print(r.text)
    r.raise_for_status()

    _ = wait_for_router(new_lan_ip)
    return new_lan_ip


def change_root_passwd(ip: str, header: dict[str, str], old_passwd: str, new_passwd: str) -> str:
    print("-" * 20 + "\033[1mChanging Root Password\033[0m" + "-" * 20)
    base_url = f"http://{ip}/api/users/config"
    r = requests.get(base_url, headers=header, verify=False)
    r.raise_for_status()
    users = r.json()

    data = {
        "data": {
            "current_password": old_passwd,
            "password": new_passwd,
            "password_confirm": new_passwd,
        }
    }

    user_id = None
    for user in users["data"]:
        if user["group"] == "root":
            user_id = user["id"]

    r = requests.put(f"{base_url}/{user_id}", json=data, headers=header, verify=False)
    print(r.text)
    r.raise_for_status()

    return new_passwd


def add_user(ip: str, header: dict[str, str], data: dict) -> None:
    print("-" * 20 + "\033[1mAdding New User\033[0m" + "-" * 20)
    base_url = f"http://{ip}/api/users/config"

    r = requests.post(base_url, json=data, headers=header, verify=False)
    print(r.text)
    r.raise_for_status()


def user_groups(ip: str, headers: dict[str, str], data: dict) -> None:
    print("-" * 20 + "\033[1mChanging User Groups\033[0m" + "-" * 20)
    base_url = f"http://{ip}/api/users/groups/config"

    r = requests.put(base_url, json=data, headers=headers, verify=False)
    print(r.text)
    r.raise_for_status()


def add_port_forwarding(ip: str, header: dict[str, str], data: dict) -> None:
    print("-" * 20 + "\033[1mAdding/Updating Port Forwarding Rule\033[0m" + "-" * 20)
    base_url = f"http://{ip}/api/firewall/port_forwards/config"

    rule_name = data["data"]["name"]
    r = requests.get(base_url, headers=header, verify=False)
    r.raise_for_status()

    existing_rule_id = None
    for rule in r.json()["data"]:
        if rule.get("name") == rule_name:
            existing_rule_id = rule["id"]
            break

    if existing_rule_id is not None:
        print(f"Updating existing port forwarding rule: {rule_name}")
        rule_data = {"data": dict(data["data"])}
        rule_data["data"].pop("id", None)
        r = requests.put(f"{base_url}/{existing_rule_id}", json=rule_data, headers=header, verify=False)
    else:
        print(f"Adding new port forwarding rule: {rule_name}")
        r = requests.post(base_url, json=data, headers=header, verify=False)

    print(r.text)
    r.raise_for_status()


def wireless_wifi(ip: str, headers: dict[str, str], wifi: dict) -> None:
    print("-" * 20 + "\033[1mConfiguring Wireless Wi-Fi\033[0m" + "-" * 20)

    if not wifi:
        print("Skipping... Wi-Fi configuration is empty.")
        return

    interfaces_url = f"http://{ip}/api/wireless/interfaces/config"

    r = requests.put(interfaces_url, headers=headers, json=wifi, verify=False)
    print(r.text)
    r.raise_for_status()


def custom_apn(ip: str, headers: dict[str, str], apn: dict) -> None:
    print("-" * 20 + "\033[1mConfiguring Custom APN\033[0m" + "-" * 20)

    if not apn:
        print("Skipping... APN configuration is empty.")
        return

    interfaces_url = f"http://{ip}/api/interfaces/config"

    r = requests.put(interfaces_url, headers=headers, json=apn, verify=False)
    print(r.text)
    r.raise_for_status()


def sim_cards(ip: str, headers: dict[str, str], sim_config: dict) -> None:
    print("-" * 20 + "\033[1mSIM Cards\033[0m" + "-" * 20)

    base_url = f"http://{ip}/api/sim_cards/config"

    r = requests.put(base_url, headers=headers, json=sim_config, verify=False)
    print(r.text)
    r.raise_for_status()


def disable_wan_interfaces(ip: str, headers: dict[str, str], wan_config: dict) -> None:
    print("-" * 20 + "\033[1mWAN Interfaces\033[0m" + "-" * 20)

    base_url = f"http://{ip}/api/interfaces/config"

    r = requests.put(base_url, headers=headers, json=wan_config, verify=False)
    print(r.text)
    r.raise_for_status()


def dhcp_ipv4_range(ip: str, headers: dict[str, str], dhcp_config: dict) -> None:
    print("-" * 20 + "\033[1mDHCP IPv4 Servers\033[0m" + "-" * 20)

    base_url = f"http://{ip}/api/dhcp/servers/ipv4/config"

    r = requests.put(base_url, headers=headers, json=dhcp_config, verify=False)
    print(r.text)
    r.raise_for_status()


def disable_rms(ip: str, headers: dict[str, str], rms_config: dict) -> None:
    print("-" * 20 + "\033[1mRMS\033[0m" + "-" * 20)

    base_url = f"http://{ip}/api/rms/config"

    r = requests.put(base_url, headers=headers, json=rms_config, verify=False)
    print(r.text)
    r.raise_for_status()


def system(ip: str, headers: dict[str, str], system_config: dict) -> None:
    print("-" * 20 + "\033[1mSystem\033[0m" + "-" * 20)

    base_url = f"http://{ip}/api/system/config"

    r = requests.put(base_url, headers=headers, json=system_config, verify=False)
    print(r.text)
    r.raise_for_status()


def change_access_control(ip: str, header: dict[str, str], type: str, data: dict) -> None:
    """
    :param type: cli, ssh or webui
    """
    print("-" * 20 + "\033[1mChanging Access Control Configuration\033[0m" + "-" * 20)
    url = f"http://{ip}/api/access_control/{type}/config"

    if type == "webui":
        for option in data.get("data", []):
            section_id = option["id"]
            section_data = {"data": dict(option)}
            section_data["data"].pop("id", None)

            r = requests.put(f"{url}/{section_id}", json=section_data, headers=header, verify=False)
            print(r.text)
            r.raise_for_status()

        return

    r = requests.put(url, json=data, headers=header, verify=False)
    print(r.text)
    r.raise_for_status()


def update_firmware(ip: str, header: dict[str, str], only_check: bool) -> None:
    url = f"http://{ip}/api/firmware/"
    check_url = f"{url}device/updates/status"
    version = None

    from time import sleep

    r = Response()
    for _ in range(30):  # ~60s total @2s delay; adjust if needed
        r = requests.get(check_url, headers=header, verify=False)
        try:
            r.raise_for_status()
            status_data = r.json()
            device_status = status_data["data"]["device"]
            if isinstance(device_status, dict):
                version = device_status["version"]
            else:
                version = device_status
            break
        except requests.exceptions.HTTPError:
            sleep(2)
            continue
    if version is None:
        raise RuntimeError(f"Could not read firmware version from status response: {r.text}")

    if version != "newest":
        print(f"There is a new version available: {version}")
        if not only_check:
            print("-" * 20 + "\033[1mUpdating Device Version From Server\033[0m" + "-" * 20)
            print("Downloading...")

            update_url = f"{url}actions/fota_download"
            r = requests.post(update_url, headers=header, verify=False)
            r.raise_for_status()

            print("Verifying Download...")
            verify_url = f"{url}actions/verify"

            for i in range(60):  # ~300s total @5s delay
                try:
                    r = requests.post(verify_url, headers=header, json={"data": {}}, verify=False)
                    if r.status_code == 200:
                        r.raise_for_status()
                        break
                    # any other status -> raise
                    r.raise_for_status()
                    break
                except requests.exceptions.HTTPError:
                    _ = sys.stdout.write(f"\rtrying {ip} ({i})... ")
                    _ = sys.stdout.flush()
                    sleep(5)
            else:
                raise RuntimeError("Firmware never became ready to verify.")

            print("Starting Upgrade...")
            upgrade_url = f"{url}actions/upgrade"
            r = requests.post(
                upgrade_url,
                headers=header,
                json={"data": {"keep_settings": "1"}},
                verify=False,
            )
            print(r.text)
            r.raise_for_status()

            _ = wait_for_router(ip, 400)

    else:
        print("Already in latest version")


def backup(ip: str, headers: dict[str, str], path: str, restore: bool) -> None:
    """
    :param path: file extension must be .../filename.tar.gz
    """
    base_url = f"http://{ip}/api/backup/actions"

    if not restore:
        print("-" * 20 + "\033[1mGenerating Backup File\033[0m" + "-" * 20)
        r = requests.post(
            f"{base_url}/generate",
            headers=headers,
            json={"data": {"encrypt": "0"}},
            verify=False,
        )
        print(r.text)
        r.raise_for_status()
        r = requests.post(f"{base_url}/download", headers=headers, json={}, stream=True, verify=False)
        r.raise_for_status()

        pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as file:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    _ = file.write(chunk)

        print("File downloaded successfully.")
    else:
        print("-" * 20 + "\033[1mRestoring From Backup File\033[0m" + "-" * 20)
        upload_data = {"file": open(path, "rb")}
        r = requests.post(
            f"{base_url}/upload",
            headers={"Authorization": headers["Authorization"]},
            files=upload_data,
            verify=False,
        )
        print(r.text)
        r.raise_for_status()
        r = requests.post(f"{base_url}/apply", headers=headers, json={"data": {}}, verify=False)
        print(r.text)
        r.raise_for_status()

        _ = wait_for_router(ip, 400)


def wait_for_router_old(ip: str, timeout: int = 300, interval: int = 5, skip_first_try: bool = False) -> bool:
    """
    Poll the router until the REST gateway replies (HTTP 401/403/200).
    Returns True when ready, False if timed out.
    """
    from time import sleep, time

    url = f"http://{ip}/api/status/device"  # HTTPS covers both GUI & API

    if not skip_first_try:
        ok_time = time()
        while time() - ok_time < 20:
            try:
                requests.get(url, timeout=2, stream=True, verify=False).close()
            except requests.RequestException:
                break

    t0 = time()
    tick = 0

    while time() - t0 < timeout:
        tick += 1
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code in (200, 401, 403):
                sys.stdout.write("\r" + " " * 60 + "\r")  # Clear the line then print success
                print("Device is available")
                return True  # GUI is up; login token required
        except requests.exceptions.RequestException:
            pass  # still booting, keep waiting

        sys.stdout.write(f"\rtrying {ip} ({tick})... ")
        sys.stdout.flush()
        sleep(interval)

    return False


def wait_for_router(ip: str, timeout: int = 300, interval: int = 5, skip_first_try: bool = False) -> bool:
    """
    Poll the router until the REST gateway replies (HTTP 401/403/200).
    Returns True when ready, False if timed out.
    """
    from time import sleep, time

    url = f"http://{ip}"

    if not skip_first_try:
        ok_time = time()
        while time() - ok_time < 20:
            try:
                requests.get(url, timeout=2, stream=True, verify=False).close()
            except requests.RequestException:
                break

    t0 = time()
    tick = 0

    while time() - t0 < timeout:
        tick += 1
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code in (200, 401, 403):
                _ = sys.stdout.write("\r" + " " * 60 + "\r")  # Clear the line then print success
                print("Device is available")
                return True  # GUI is up; login token required
        except requests.exceptions.RequestException:
            pass  # still booting, keep waiting

        _ = sys.stdout.write(f"\rtrying {ip} ({tick})... ")
        _ = sys.stdout.flush()
        sleep(interval)

    return False


def sim_card_activate(ip: str, headers: dict[str, str], pin: str) -> None:
    print("-" * 20 + "\033[1mUnlocking SIM Card\033[0m" + "-" * 20)
    status_url = f"http://{ip}/api/modems/status/"
    r = requests.get(status_url, headers=headers, verify=False).json()

    modem_id = r["data"][0]["id"]
    modem_url = f"http://{ip}/api/modems/status/{modem_id}"

    r = requests.get(modem_url, headers=headers, verify=False).json()

    pinstate = r["data"]["pinstate"]
    if not pinstate.__contains__("Required PIN"):
        print(f"Skipping...  SIM state is: {pinstate}")
        return

    unlock_url = f"http://{ip}/api/modems/{modem_id}/actions/sim_unlock"
    r = requests.post(unlock_url, headers=headers, json={"data": {"pin": str(pin)}}, verify=False)
    print(r.text)
    r.raise_for_status()


def auto_reboot(ip: str, headers: dict[str, str], data: dict) -> None:
    print("-" * 20 + "\033[1mChanging Auto Reboot Options\033[0m" + "-" * 20)

    config_url = f"http://{ip}/api/auto_reboot/ping_wget/config"

    r = requests.put(config_url, headers=headers, json=data, verify=False)
    print(r.text)
    r.raise_for_status()


def sms_utilities(ip: str, headers: dict[str, str], config: dict) -> None:
    print("-" * 20 + "\033[1mChanging SMS Utilities\033[0m" + "-" * 20)

    config_url = f"http://{ip}/api/sms_utilities/rules/config"

    if "enable_list" in config:
        enable_list = config["enable_list"]
    else:
        enable_list = [
            option.get("smstext", option.get("action", ""))
            for option in config.get("data", [])
            if option.get("enabled", "1") == "1"
        ]

    if not enable_list:
        print("Skipping... SMS utilities enable list is empty.")
        return

    r = requests.get(config_url, headers=headers, verify=False)
    r.raise_for_status()
    data = []

    for option in r.json()["data"]:
        if option["smstext"] in enable_list or enable_list[0] == "all":
            data.append({"id": option["id"], "enabled": "1"})
        else:
            data.append({"id": option["id"], "enabled": "0"})

    r = requests.put(config_url, headers=headers, json={"data": data}, verify=False)
    print(r.text)
    r.raise_for_status()


def ntp(ip: str, headers: dict[str, str], data: dict) -> None:
    print("-" * 20 + "\033[1mChanging NTP Settings\033[0m" + "-" * 20)

    client_url = f"http://{ip}/api/date_time/ntp/client/config"
    server_url = f"http://{ip}/api/date_time/ntp/server/config"
    timeserver_url = f"http://{ip}/api/date_time/ntp/time_servers/config"

    if "client" in data:
        r = requests.put(client_url, headers=headers, json=data["client"], verify=False)
        print(r.text)
        r.raise_for_status()

    if "server" in data:
        r = requests.put(server_url, headers=headers, json=data["server"], verify=False)
        print(r.text)
        r.raise_for_status()

    if "timeservers" in data:
        r = requests.put(timeserver_url, headers=headers, json=data["timeservers"], verify=False)
        print(r.text)
        r.raise_for_status()

    if "timeservers_delete" in data:
        r = requests.delete(timeserver_url, headers=headers, json=data["timeservers_delete"], verify=False)
        print(r.text)
        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError:
            if r.status_code in (400, 404) and "does not exist" in r.text:
                print("Warning: one or more NTP time servers were already deleted.")
            else:
                raise
