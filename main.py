import urllib3

from task_cli import load_template_config, run_configuration_cli, select_template

urllib3.disable_warnings()


def wait_before_exit() -> None:
    try:
        input("\nPulsa Enter para cerrar...")
    except EOFError:
        pass


def main() -> int:
    try:
        template_name = select_template()
        conf = load_template_config(template_name)

        run_configuration_cli(conf)
        wait_before_exit()
        return 0

    except KeyboardInterrupt:
        print("\n\nEjecución cancelada por el usuario.")
        wait_before_exit()
        return 130

    except Exception as error:
        print(f"\nError inesperado: {type(error).__name__}: {error}")
        wait_before_exit()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
