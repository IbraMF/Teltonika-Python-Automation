from __future__ import annotations

import importlib.util
import pathlib
import sys
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from InquirerPy import inquirer
from InquirerPy.base.control import Choice
from InquirerPy.prompts.checkbox import CheckboxPrompt

import other
from vpn import OpenVPN, Wireguard

SELECT_ALL_KEY = "__select_all__"
BASIC_OFFLINE_GROUP_KEY = "__group_basic_offline__"
OTHERS_GROUP_KEY = "__group_others__"

CLI_KEYBINDINGS = {
    "up": [
        {"key": "up"},
        {"key": "k"},
        {"key": "h"},
    ],
    "down": [
        {"key": "down"},
        {"key": "j"},
        {"key": "l"},
    ],
    "answer": [
        {"key": "enter"},
    ],
    "interrupt": [
        {"key": "c-c"},
    ],
}


class GroupedCheckboxPrompt(CheckboxPrompt):
    def __init__(
        self,
        *,
        task_keys: set[str],
        group_task_keys: dict[str, set[str]],
        **kwargs: Any,
    ) -> None:
        self.task_keys = task_keys
        self.group_task_keys = group_task_keys
        super().__init__(**kwargs)

    def _selected_task_keys(self) -> set[str]:
        return {
            choice["value"]
            for choice in self.content_control.choices
            if choice["value"] in self.task_keys and choice["enabled"]
        }

    def _all_tasks_selected(self) -> bool:
        return self._selected_task_keys() == self.task_keys

    def _group_selected(self, group_key: str) -> bool:
        return self.group_task_keys[group_key] <= self._selected_task_keys()

    def _set_group_tasks(self, group_key: str, enabled: bool) -> None:
        group_tasks = self.group_task_keys[group_key]

        for choice in self.content_control.choices:
            if choice["value"] in group_tasks or choice["value"] == group_key:
                choice["enabled"] = enabled

    def _set_all_tasks(self, enabled: bool) -> None:
        for choice in self.content_control.choices:
            if choice["value"] in self.task_keys | self.group_task_keys.keys() | {SELECT_ALL_KEY}:
                choice["enabled"] = enabled

    def _sync_parent_choices(self) -> None:
        parent_states = {
            SELECT_ALL_KEY: self._all_tasks_selected(),
            **{
                group_key: self._group_selected(group_key)
                for group_key in self.group_task_keys
            },
        }

        for choice in self.content_control.choices:
            if choice["value"] in parent_states:
                choice["enabled"] = parent_states[choice["value"]]

    def _handle_toggle_choice(self, _: Any) -> None:
        selected_value = self.content_control.selection["value"]

        if selected_value == SELECT_ALL_KEY:
            should_select_all = not self._all_tasks_selected()
            self._set_all_tasks(should_select_all)
            return

        if selected_value in self.group_task_keys:
            should_select_group = not self._group_selected(selected_value)
            self._set_group_tasks(selected_value, should_select_group)
            self._sync_parent_choices()
            return

        super()._handle_toggle_choice(_)
        self._sync_parent_choices()


class ErrorAction(str, Enum):
    RETRY = "retry"
    SKIP = "skip"
    EXIT = "exit"


class TaskSkipped(Exception):
    pass


@dataclass(frozen=True)
class Task:
    key: str
    label: str
    fn: Callable[[], None]


@dataclass
class RuntimeContext:
    conf: dict[str, Any]
    headers: Any


def get_app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent

    return Path(__file__).parent


def get_templates_dir() -> Path:
    return get_app_dir() / "plantillas"


def get_available_templates() -> list[str]:
    templates_dir = get_templates_dir()

    templates: list[str] = []

    for file in templates_dir.glob("*.py"):
        if file.name == "__init__.py":
            continue

        templates.append(file.stem)

    return sorted(templates)


def select_template() -> str:
    templates = get_available_templates()

    if not templates:
        raise RuntimeError("No se encontraron plantillas en la carpeta 'plantillas'.")

    try:
        return inquirer.select(
            message="Selecciona la plantilla a utilizar:",
            choices=templates,
            instruction="Usa ↑/↓ y Enter para confirmar",
            mandatory=False,
            vi_mode=True,
            keybindings=CLI_KEYBINDINGS,
        ).execute()

    except KeyboardInterrupt:
        print("\nSelección de plantilla cancelada.")
        raise


def load_template_config(template_name: str) -> dict[str, Any]:
    template_path = get_templates_dir() / f"{template_name}.py"
    spec = importlib.util.spec_from_file_location(f"plantillas.{template_name}", template_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"No se pudo cargar la plantilla '{template_path}'.")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    try:
        config = module.config
    except AttributeError as error:
        raise RuntimeError(f"La plantilla 'plantillas.{template_name}' no tiene una variable 'config'.") from error

    return config


def select_task_keys(tasks: list[Task]) -> set[str]:
    task_keys = {task.key for task in tasks}
    basic_offline_keys = {"lan", "update", "root", "user"}
    group_task_keys = {
        BASIC_OFFLINE_GROUP_KEY: basic_offline_keys,
        OTHERS_GROUP_KEY: task_keys - basic_offline_keys,
    }

    choices = [
        Choice(value=SELECT_ALL_KEY, name="Seleccionar / deseleccionar todo", enabled=False),
        Choice(value=BASIC_OFFLINE_GROUP_KEY, name="Basic offline", enabled=False),
        *[
            Choice(value=task.key, name=f"  {task.label}", enabled=False)
            for task in tasks
            if task.key in group_task_keys[BASIC_OFFLINE_GROUP_KEY]
        ],
        Choice(value=OTHERS_GROUP_KEY, name="Others", enabled=False),
        *[
            Choice(value=task.key, name=f"  {task.label}", enabled=False)
            for task in tasks
            if task.key in group_task_keys[OTHERS_GROUP_KEY]
        ],
    ]

    try:
        selected = GroupedCheckboxPrompt(
            message="Selecciona las tareas a ejecutar:",
            choices=choices,
            task_keys=task_keys,
            group_task_keys=group_task_keys,
            instruction="Usa ↑/↓, espacio para marcar/desmarcar, Enter para confirmar",
            height=10,
            cycle=False,
            mandatory=False,
            vi_mode=True,
            keybindings=CLI_KEYBINDINGS,
        ).execute()

    except KeyboardInterrupt:
        print("\nSelección de tareas cancelada.")
        raise

    return {key for key in selected if key in task_keys}


def ask_error_action(task: Task, error: Exception) -> ErrorAction:
    print()
    print(f"❌ Error ejecutando tarea: {task.label}")
    print(f"{type(error).__name__}: {error}")
    print()

    try:
        action = inquirer.select(
            message="¿Qué quieres hacer?",
            choices=[
                Choice(value=ErrorAction.RETRY, name="Repetir desde la última tarea fallida"),
                Choice(value=ErrorAction.SKIP, name="Ignorar tarea fallida y continuar"),
                Choice(value=ErrorAction.EXIT, name="Finalizar ejecución"),
            ],
            mandatory=False,
            vi_mode=True,
            keybindings=CLI_KEYBINDINGS,
        ).execute()

    except KeyboardInterrupt:
        print("\nEjecución cancelada.")
        raise

    return ErrorAction(action)


def run_selected_tasks(tasks: list[Task]) -> None:
    index = 0

    while index < len(tasks):
        task = tasks[index]

        try:
            print(f"\n▶ Ejecutando: {task.label}")
            task.fn()
            print(f"✅ Completada: {task.label}")
            index += 1

        except KeyboardInterrupt:
            print(f"\n\nEjecución cancelada durante la tarea: {task.label}")
            raise

        except TaskSkipped as skipped:
            print(f"⚠️ Tarea ignorada: {task.label}: {skipped}")
            index += 1
            continue

        except Exception as error:
            action = ask_error_action(task, error)

            if action == ErrorAction.RETRY:
                continue

            if action == ErrorAction.SKIP:
                print(f"⚠️ Tarea ignorada: {task.label}")
                index += 1
                continue

            if action == ErrorAction.EXIT:
                print("Ejecución finalizada.")
                return

    print("\n✅ Ejecución terminada.")


def is_empty_config(value: Any) -> bool:
    if value is None:
        return True

    if isinstance(value, str):
        return value == ""

    if isinstance(value, dict):
        if len(value) == 0:
            return True

        if set(value.keys()) == {"data"}:
            return is_empty_config(value["data"])

        return all(is_empty_config(item) for item in value.values())

    if isinstance(value, list | tuple | set):
        return len(value) == 0

    return False


def skip_task_if_empty(field_name: str, value: Any) -> None:
    if is_empty_config(value):
        raise TaskSkipped(f"template field '{field_name}' is empty or missing")


def get_system_device_name(system: dict[str, Any]) -> str:
    for item in system.get("data", []):
        if "devicename" in item:
            return item["devicename"]

        if "hostname" in item:
            return item["hostname"]

    return ""


def build_tasks(ctx: RuntimeContext) -> list[Task]:
    conf = ctx.conf

    cur = conf["current"]
    exp = conf["expected"]
    wg = conf.get("wg", {})
    ovpn = conf.get("ovpn", {})
    new_users = conf.get("new_users", {})
    user_groups = conf.get("user_groups", {})
    ac = conf.get("access_control", {})
    portf = conf.get("port_forwarding", {})
    auto = conf.get("auto_reboot", {})
    sms = conf.get("sms_utilities", {})
    ntp = conf.get("ntp", {})
    wifi = conf.get("wifi", {})
    apn = conf.get("apn", {})
    sim_cards = conf.get("sim_cards", {})
    wan_interfaces = conf.get("wan_interfaces", {})
    dhcp_ipv4 = conf.get("dhcp_ipv4", {})
    rms = conf.get("rms", {})
    system = conf.get("system", {})
    backup = conf.get("backup", {})
    sim_pin = conf.get("sim_pin")

    def task_lan() -> None:
        ip = other.change_lan(cur["ip"], ctx.headers, exp["ip"], exp["mask"], None)
        ctx.headers = other.login(ip, cur["username"], cur["password"])

    def task_update() -> None:
        other.update_firmware(exp["ip"], ctx.headers, only_check=False)
        ctx.headers = other.login(exp["ip"], cur["username"], cur["password"])

    def task_wireguard() -> None:
        skip_task_if_empty("wg", wg)

        wireguard_client = Wireguard(exp["ip"], ctx.headers)
        wg_config = wg.get("config", wg)
        wireguard_client.create_instance(wg_config["data"])

        for interface_id, peers in wg.get("peers", {}).items():
            for peer in peers:
                peer_data = peer["data"]
                wireguard_client.add_peer(
                    interface_id,
                    peer_data["id"],
                    peer_data["public_key"],
                    peer_data["allowed_ips"],
                    peer_data.get("route_allowed_ips", "1"),
                    peer_data.get("persistent_keepalive", "25"),
                )

    def task_openvpn() -> None:
        skip_task_if_empty("ovpn", ovpn)

        openvpn_client = OpenVPN(exp["ip"], ctx.headers)
        ovpn_config = ovpn.get("config", ovpn)
        openvpn_client.create_instance(ovpn_config["data"], ovpn["common_name"], pathlib.Path(ovpn["cert_dir"]))

    def task_root() -> None:
        other.change_root_passwd(exp["ip"], ctx.headers, cur["password"], exp["password"])

    def task_user() -> None:
        skip_task_if_empty("new_users", new_users)

        users = new_users if isinstance(new_users, list) else new_users.values()

        for user in users:
            other.add_user(exp["ip"], ctx.headers, user)

    def task_user_groups() -> None:
        skip_task_if_empty("user_groups", user_groups)

        other.user_groups(exp["ip"], ctx.headers, user_groups)

    def task_access_control() -> None:
        skip_task_if_empty("access_control", ac)

        access_items = [(access_type, data) for access_type, data in ac.items() if access_type != "webui"]
        if "webui" in ac:
            access_items.append(("webui", ac["webui"]))

        for access_type, data in access_items:
            if is_empty_config(data):
                print(f"Skipping... access_control.{access_type} is empty.")
                continue

            other.change_access_control(exp["ip"], ctx.headers, access_type, data)

    def task_port_forwarding() -> None:
        skip_task_if_empty("port_forwarding", portf)

        rules = portf if isinstance(portf, list) else portf.values()

        for rule in rules:
            other.add_port_forwarding(exp["ip"], ctx.headers, rule)

    def task_auto_reboot() -> None:
        skip_task_if_empty("auto_reboot", auto)

        other.auto_reboot(exp["ip"], ctx.headers, auto)

    def task_sms_utilities() -> None:
        skip_task_if_empty("sms_utilities", sms)

        other.sms_utilities(exp["ip"], ctx.headers, sms)

    def task_ntp_time() -> None:
        skip_task_if_empty("ntp", ntp)

        ntp_data = {}
        for key, data in ntp.items():
            if is_empty_config(data):
                print(f"Skipping... ntp.{key} is empty.")
                continue

            ntp_data[key] = data

        other.ntp(exp["ip"], ctx.headers, ntp_data)

    def task_wifi() -> None:
        skip_task_if_empty("wifi", wifi)

        other.wireless_wifi(exp["ip"], ctx.headers, wifi)

    def task_apn() -> None:
        skip_task_if_empty("apn", apn)

        other.custom_apn(exp["ip"], ctx.headers, apn)

    def task_sim_cards() -> None:
        skip_task_if_empty("sim_cards", sim_cards)

        other.sim_cards(exp["ip"], ctx.headers, sim_cards)

    def task_disable_wan_interfaces() -> None:
        skip_task_if_empty("wan_interfaces", wan_interfaces)

        other.disable_wan_interfaces(exp["ip"], ctx.headers, wan_interfaces)

    def task_dhcp_ipv4_range() -> None:
        skip_task_if_empty("dhcp_ipv4", dhcp_ipv4)

        other.dhcp_ipv4_range(exp["ip"], ctx.headers, dhcp_ipv4)

    def task_rms() -> None:
        skip_task_if_empty("rms", rms)

        other.disable_rms(exp["ip"], ctx.headers, rms)

    def task_system() -> None:
        skip_task_if_empty("system", system)

        other.system(exp["ip"], ctx.headers, system)

    def task_sim_card() -> None:
        skip_task_if_empty("sim_pin", sim_pin)

        other.sim_card_activate(exp["ip"], ctx.headers, sim_pin)

    def task_backup() -> None:
        device_name = get_system_device_name(system)
        backup_name = device_name or ovpn.get("common_name", "")
        backup_dir = backup.get("backup_dir", ovpn.get("backup_dir", ".\\backup"))
        backup_path = backup.get("path", f"{backup_dir}\\{backup_name}.tar.gz" if backup_name else "")
        backup_config = {"path": backup_path, "restore": backup.get("restore", False)}

        skip_task_if_empty("backup.path", backup_path)

        other.backup(exp["ip"], ctx.headers, backup_config["path"], restore=backup_config.get("restore", False))

    return [
        Task("lan", "LAN", task_lan),
        Task("update", "Firmware", task_update),
        Task("wireguard", "WireGuard", task_wireguard),
        Task("openvpn", "OpenVPN", task_openvpn),
        Task("root", "Users root password", task_root),
        Task("user", "Users", task_user),
        Task("user_groups", "User groups", task_user_groups),
        Task("access_control", "Access control", task_access_control),
        Task("port_forwarding", "Firewall port forwards", task_port_forwarding),
        Task("auto_reboot", "Auto reboot", task_auto_reboot),
        Task("sms_utilities", "SMS utilities", task_sms_utilities),
        Task("ntp_time", "NTP", task_ntp_time),
        Task("wifi", "Wireless interfaces", task_wifi),
        Task("apn", "Interfaces APN", task_apn),
        Task("sim_cards", "SIM cards", task_sim_cards),
        Task("disable_wan_interfaces", "WAN interfaces", task_disable_wan_interfaces),
        Task("dhcp_ipv4_range", "DHCP IPv4 servers", task_dhcp_ipv4_range),
        Task("rms", "RMS", task_rms),
        Task("system", "System", task_system),
        Task("sim_card", "SIM unlock", task_sim_card),
        Task("backup", "Backup", task_backup),
    ]


def run_configuration_cli(conf: dict[str, Any]) -> None:
    preview_ctx = RuntimeContext(conf=conf, headers=None)
    all_tasks = build_tasks(preview_ctx)

    selected_keys = select_task_keys(all_tasks)

    if not selected_keys:
        print("No se seleccionó ninguna tarea.")
        return

    selected_tasks = [task for task in all_tasks if task.key in selected_keys]

    print("\nTareas seleccionadas:")
    for task in selected_tasks:
        print(f" - {task.label}")

    should_continue = inquirer.confirm(message="¿Ejecutar estas tareas?", default=True).execute()

    if not should_continue:
        print("Ejecución cancelada.")
        return

    cur = conf["current"]
    exp = conf["expected"]

    # Misma lógica que tenías antes:
    # Si se va a cambiar LAN, primero se entra por la IP actual.
    # Si no, se entra por la IP esperada.
    login_ip_data = cur if "lan" in selected_keys else exp

    # Si se va a cambiar root, el primer login usa la contraseña actual.
    # Si no, usa la esperada.
    login_password_data = cur if "root" in selected_keys else exp

    headers = other.login(login_ip_data["ip"], cur["username"], login_password_data["password"], True)

    ctx = RuntimeContext(conf=conf, headers=headers)

    # Rehacemos las tasks con el contexto real, ya con headers.
    executable_tasks = [task for task in build_tasks(ctx) if task.key in selected_keys]

    run_selected_tasks(executable_tasks)
