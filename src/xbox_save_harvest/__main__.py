"""Entry point for `python -m xbox_save_harvest` and standalone PyInstaller builds."""

from xbox_save_harvest.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
