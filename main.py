from vpn import Wireguard, OpenVPN
import other, urllib3

urllib3.disable_warnings()

if __name__ == "__main__":
    

    # ----------------------------- ENTERPRISE 1 ----------------------------- 

    ip = "192.168.1.1"
    username = "admin"
    password = "password"
    common_name = "COMMON_NAME" # poner certificados en cert_dir
    cert_dir = "C:\\Users\\USER\\Downloads\\cert"
    backup_dir = "C:\\Users\\USER\\Downloads\\cert\\backup"

    lan = True
    update = True 
    wg = True
    op = True 
    root = True 
    user = True 
    ac = True 
    portf = True 
    sim_card = True
    backup = True
    

    headers = other.login(ip, username, password, True)

    if lan:
        ip = other.change_lan(ip, headers, "192.168.10.1", "255.255.255.0", None)
        headers = other.login(ip, username, password)
    if update:
        other.update_firmware(ip, headers, only_check=False)
        headers = other.login(ip, username, password)
    if wg:
        wg = Wireguard(ip, headers)
        wg.create_instance(
            "wg0", 
            "PRIVATEKEY", "PUBLICKEY", 
            "51820", ["172.16.0.1/32"],
            "PEER", "PRIVATEPEERKEY", ["172.16.0.0/24"])
    if op:
        op = OpenVPN(ip, headers)
        op.create_instance(
            "ovpn0", "1194", 
            ca_path=f"{cert_dir}\\ca.crt", 
            cert_path=f"{cert_dir}\\{common_name}.crt", 
            key_path=f"{cert_dir}\\{common_name}.key", 
            remote_host="SERVER_ENDPOINT", ip="10.0.0.0", mask="255.255.255.0")
    if root:
        password = other.change_root_passwd(ip, headers, password, "NEWPASSWORD")
    if user:
        other.add_user(ip, headers, "NEWUSERNAME", "NEWUSERNAMEPASSWORD", "admin")
    if ac:
        other.change_access_control(ip, header=headers, type="ssh", enabled=False, wan_access=False)
        other.change_access_control(ip, header=headers, type="cli", enabled=False, wan_access=False)
    if portf:
        other.add_port_forwarding(ip, headers, "NAME", ["tcp"], "openvpn", "5000", "192.168.10.2", "5000")
        other.add_port_forwarding(ip, headers, "NAME", ["udp", "tcp"], "openvpn", "443", "192.168.10.3", "443")
    if sim_card:
        other.sim_card_activate(ip, headers, SIM_pin)
    if backup:
        other.backup(ip, headers, f"{backup_dir}\\{common_name}.tar.gz", restore=False)   
