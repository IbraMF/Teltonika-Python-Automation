from vpn import Wireguard, OpenVPN
import other, urllib3

urllib3.disable_warnings()

if __name__ == "__main__":

    lan = False
    update = False 
    wireguard = False
    openvpn = False 
    root = False 
    user = False 
    access_control = False 
    port_forwarding = False
    auto_reboot = False
    sms_utilities = False
    ntp_time = False
    sim_card = False
    backup = True

    ###### PLANTILLA A UTILIZAR ######
    from plantillas.test import config as conf
    ##################################

    cur = conf['current']
    exp = conf['expected']
    wg = conf['wg']
    ovpn = conf['ovpn']
    new_users = conf['new_users']
    ac = conf['access_control']
    portf = conf['port_forwarding']
    auto = conf['auto_reboot']
    sms = conf['sms_utilities']
    ntp = conf['ntp']


    headers = other.login(cur['ip'], cur['username'], cur['password'], True)

    if lan:
        ip = other.change_lan(cur['ip'], headers, exp['ip'], exp['mask'], None)
        headers = other.login(ip, cur['username'], cur['password'])
    if update:
        other.update_firmware(exp['ip'], headers, only_check=False)
        headers = other.login(exp['ip'], cur['username'], cur['password'])
    if wireguard:
        wireguard = Wireguard(exp['ip'], headers)
        wireguard.create_instance(wg['name'], wg['private_key'], wg['public_key'], wg['port'], wg['ip'])
        for peername in wg['peers'].keys():
            peer = wg['peers'][peername]
            wireguard.add_peer(wg['name'], peername, peer['public_key'], peer['ip'], peer.get('route_allowed', "1"), peer.get('keepalive', "25"))
    if openvpn:
        openvpn = OpenVPN(exp['ip'], headers)
        openvpn.create_instance(
            ovpn['name'], ovpn['protocol'], ovpn['port'], 
            ca_path=f"{ovpn['cert_dir']}\\ca.crt", 
            cert_path=f"{ovpn['cert_dir']}\\{ovpn['common_name']}.crt", 
            key_path=f"{ovpn['cert_dir']}\\{ovpn['common_name']}.key", 
            remote_host=ovpn['server'], ip=ovpn['ip'], mask=ovpn['mask'])
    if root:
        password = other.change_root_passwd(exp['ip'], headers, cur['password'], exp['password'])
    if user:
        for username in new_users:
            aux = new_users[username]
            other.add_user(exp['ip'], headers, username, aux['password'], aux['type'])
    if access_control:
        for type in ac:
            aux = ac[type]
            other.change_access_control(exp['ip'], headers, type, aux['enabled'], aux['wan_access'])
    if port_forwarding:
        for rulename in portf:
            aux = portf[rulename]
            other.add_port_forwarding(exp['ip'], headers, rulename, aux['proto'], aux['source'], aux['source_port'], aux['dest_ip'], aux['dest_port'])
    if auto_reboot:
        other.auto_reboot(exp['ip'], headers, auto['enable'], auto['retry'], auto['timeout'])
    if sms_utilities:
        other.sms_utilities(exp['ip'], headers, sms['enable_list'])
    if ntp_time:
        other.ntp(exp['ip'], headers, ntp['timezone'], ntp['client_enable'], ntp['server_enable'], ntp['force_servers'], ntp['interval'], ntp['operator_sync'], ntp['timeservers'])
    if sim_card:
        other.sim_card_activate(exp['ip'], headers, conf['sim_pin'])
    if backup:
        other.backup(exp['ip'], headers, f"{ovpn['backup_dir']}\\{ovpn['common_name']}.tar.gz", restore=False)   


# nombre de dispositivo
