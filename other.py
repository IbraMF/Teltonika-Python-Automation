import requests, json, sys

def login(ip, user, password, is_wait_for_router: bool = False):

    if is_wait_for_router:
        wait_for_router(ip, skip_first_try=True)

    url = f'http://{ip}/api/login'
    login_data = {'username': user, 'password': password}
    headers = {'Content-type': 'application/json'}

    login = requests.post(url, json = login_data, headers=headers, verify=False)
    login_out = json.loads(login.text)

    if login_out['success']:
        token = login_out['data']['token']
        print("Login Correcto")
        headers['Authorization'] = f'Bearer {token}'
        return headers
    else:
        raise Exception(f"Error en el login: {login_out}")

def change_lan(ip, header, new_lan_ip, mask, gateway = None) -> str:
    print("-"*20+"\033[1mChanging LAN IP/MASK\033[0m"+"-"*20)

    base_url = f"http://{ip}/api/interfaces/config/lan"
    
    data = {"data": {
            "ipaddr": new_lan_ip,
            "netmask": mask
        }}
    
    if gateway is not None:
        data["gateway"] = gateway

    r = requests.put(base_url, headers=header, json=data, verify=False)
    print(r.text)
    r.raise_for_status()

    wait_for_router(new_lan_ip)
    return new_lan_ip

def change_root_passwd(ip, header, old_passwd, new_passwd) -> str:
    print("-"*20+"\033[1mChanging Root Password\033[0m"+"-"*20)
    base_url = f"http://{ip}/api/users/config"
    r = requests.get(base_url, headers=header, verify=False)
    r.raise_for_status()
    users = r.json()

    data = {"data": {
            "current_password": old_passwd,
            "password": new_passwd,
            "password_confirm": new_passwd
        }}
    
    for user in users["data"]:
        if user["group"] == "root":
            user_id = user["id"]

    r = requests.put(f"{base_url}/{user_id}", json=data, headers=header, verify=False)
    print(r.text)
    r.raise_for_status()

    return new_passwd

def add_user(ip, header, username, passwd, group):
    """
    :param passwd:  between 8 - 4094 characters, at least 1 uppercase, 1 lowercase, 1 number, 1 special character
    :param group:   admin or user
    """
    print("-"*20+"\033[1mAdding New User\033[0m"+"-"*20)
    base_url = f"http://{ip}/api/users/config"

    data = {"data": {
            "username": username,
            "password": passwd,
            "group": group
        }}

    r = requests.post(base_url, json=data, headers=header, verify=False)
    print(r.text)
    r.raise_for_status()

def add_port_forwarding(ip, header, name, protocols: list[str], src_zone, src_dport, dest_ip, dest_port):
    print("-"*20+"\033[1mAdding New Port Forwarding Rule\033[0m"+"-"*20)
    base_url = f"http://{ip}/api/firewall/port_forwards/config"

    data = {"data": {
            "enabled": "1",
            "name": name,
            "proto": protocols,
            "src": src_zone,
            "src_dport": src_dport,
            "dest_ip": dest_ip,
            "dest_port": dest_port
        }}

    r = requests.post(base_url, json=data, headers=header, verify=False)
    print(r.text)
    r.raise_for_status()

def change_access_control(ip, header, type: str, enabled: bool, wan_access: bool, port = None):
    """
    :param type: cli, ssh or webui
    """
    print("-"*20+"\033[1mChanging Access Control Configuration\033[0m"+"-"*20)
    url = f"http://{ip}/api/access_control/{type}/config"

    data = {"data": [{
            "id": "general",
            "enabled": str(int(enabled)),
            "wan_access": str(int(wan_access))
        }]}
    
    if port is not None:
        data["port"] = port
    
    r = requests.put(url, json=data, headers=header, verify=False)
    print(r.text)
    r.raise_for_status()

def update_firmware(ip, header, only_check):
    url = f"http://{ip}/api/firmware/"
    check_url = f"{url}device/updates/status"
    version = None

    from time import sleep

    for _ in range(30):  # ~60s total @2s delay; adjust if needed
        r = requests.get(check_url, headers=header, verify=False)
        try:
            r.raise_for_status()
            version = r.json()["data"]["device"]["version"]
            break
        except (requests.exceptions.HTTPError):
            sleep(2)
            continue
    if version is None:
        raise RuntimeError("Could not read firmware version from status response.")

    version = r.json()["data"]["device"]["version"]
    if version != "newest":
        print(f"There is a new version available: {version}")
        if not only_check:
            print("-"*20+"\033[1mUpdating Device Version From Server\033[0m"+"-"*20)
            print("Downloading...")

            update_url = f"{url}actions/fota_download"
            r = requests.post(update_url, headers=header, verify=False)
            r.raise_for_status()

            print("Verifying Download...")
            verify_url = f"{url}actions/verify"

            for _ in range(60):  # ~300s total @5s delay
                try:
                    r = requests.post(verify_url, headers=header, json={"data": {}}, verify=False)
                    if r.status_code == 200:
                        r.raise_for_status()
                        break
                    # any other status -> raise
                    r.raise_for_status()
                    break
                except requests.exceptions.HTTPError:
                    sleep(5)
            else:
                raise RuntimeError("Firmware never became ready to verify.")

            print("Starting Upgrade...")
            upgrade_url = f"{url}actions/upgrade"
            r = requests.post(upgrade_url, headers=header, json={"data": {"keep_settings": "1"}}, verify=False)
            print(r.text)
            r.raise_for_status()

            wait_for_router(ip, 400)
            
    else:
        print("Already in latest version")


def backup(ip, headers, path, restore: bool):
    """
    :param path: file extension must be .../filename.tar.gz
    """
    base_url = f"http://{ip}/api/backup/actions"

    if not restore:
        print("-"*20+"\033[1mGenerating Backup File\033[0m"+"-"*20)
        r = requests.post(f"{base_url}/generate", headers=headers, json={"data": {"encrypt": "0"}}, verify=False)
        print(r.text)
        r.raise_for_status()
        r = requests.post(f"{base_url}/download", headers=headers, json={}, stream=True, verify=False)
        print(r.text)
        r.raise_for_status()

        with open(path, "wb") as file:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    file.write(chunk)

        print("File downloaded successfully.")
    else:
        print("-"*20+"\033[1mRestoring From Backup File\033[0m"+"-"*20)
        upload_data = {"file": open(path, "rb")}
        r = requests.post(f"{base_url}/upload", headers={"Authorization": headers["Authorization"]}, files=upload_data, verify=False)
        print(r.text)
        r.raise_for_status()
        r = requests.post(f"{base_url}/apply", headers=headers, json={"data":{}}, verify=False)
        print(r.text)
        r.raise_for_status()

        wait_for_router(ip, 400)


def wait_for_router(ip: str, timeout: int = 300, interval: int = 5, skip_first_try: bool = False) -> bool:
    """
    Poll the router until the REST gateway replies (HTTP 401/403/200).
    Returns True when ready, False if timed out.
    """
    from time import time, sleep
    url = f"http://{ip}/api/status/device"     # HTTPS covers both GUI & API

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
                sys.stdout.write("\r" + " " * 60 + "\r")    # Clear the line then print success
                print("Device is available")
                return True                     # GUI is up; login token required
        except requests.exceptions.RequestException:        
            pass                                # still booting, keep waiting

        sys.stdout.write(f"\rtrying {tick}... ")
        sys.stdout.flush()
        sleep(interval)

    return False

def sim_card_activate(ip, headers, pin):
    print("-"*20+"\033[1mUnlocking SIM Card\033[0m"+"-"*20)
    status_url = f"http://{ip}/api/modems/status/1-1"
    r = requests.get(status_url, headers=headers, verify=False).json()
    print(r['data']['pinstate'])

    unlock_url = f"http://{ip}/api/modems/1-1/actions/sim_unlock"
    r = requests.post(unlock_url, headers=headers, json = {"data": {"pin": str(pin)}}, verify=False)
    print(r.text)
    r.raise_for_status()

def auto_reboot(ip, headers, enable, retry, timeout):
    print("-"*20+"\033[1mChanging Auto Reboot Options\033[0m"+"-"*20)

    config_url = f"http://{ip}/api/auto_reboot/ping_wget/config"
    r = requests.get(config_url, headers=headers)
    r.raise_for_status()

    id = r.json()['data'][0]['id']
    data = {"data": [{
        "id": id,
        "enable": str(int(enable)),
        "retry": str(retry),
        "time_out": str(timeout)
        }]
    }

    r = requests.put(config_url, headers=headers, json = data)
    print(r.text)
    r.raise_for_status()
    
def sms_utilities(ip, headers, enable_list):
    print("-"*20+"\033[1mChanging SMS Utilities\033[0m"+"-"*20)

    config_url = f"http://{ip}/api/sms_utilities/rules/config"
    r = requests.get(config_url, headers=headers).json()
    data = []
    
    for option in r['data']:
        if option['smstext'] in enable_list or enable_list[0] == "all":            
            data.append({"id": option['id'], "enabled" : "1"})
        else:
            data.append({"id": option['id'], "enabled" : "0"})

    r = requests.put(config_url, headers=headers, json = {'data': data})
    r.raise_for_status()
    print({"success": "true", "data": enable_list})

def ntp(ip, headers, timezone, client_enable, server_enable, force_servers, interval, operator_sync, timeservers):
    print("-"*20+"\033[1mChanging NTP Settings\033[0m"+"-"*20)

    client_url = f"http://{ip}/api/date_time/ntp/client/config"
    server_url = f"http://{ip}/api/date_time/ntp/server/config"
    timeserver_url = f"http://{ip}/api/date_time/ntp/time_servers/config"

    client_data = {'data': [{
        'id': 'ntpclient',
        'zoneName': timezone,
        'enabled': str(int(client_enable)),
        'force': str(int(force_servers)),
        'interval': interval,
        'sync_enabled': str(int(operator_sync))
        }]    
    }

    r = requests.put(client_url, headers=headers, json = client_data)
    print(r.text)
    r.raise_for_status()

    server_data = {'data': [{
        'id': 'general',
        'enabled': str(int(server_enable))
        }]
    }

    r = requests.put(server_url, headers=headers, json = server_data)
    print(r.text)
    r.raise_for_status()

    timeserver_data = []
    for id, value in timeservers.items():
        timeserver_data.append({'id': id, 'hostname': value })

    r = requests.put(timeserver_url, headers=headers, json={'data': timeserver_data})
    print(r.text)
    r.raise_for_status()
