"""Entry point for the packaged executables (PyInstaller runs this as a top-level script)."""
import sys

from hardline.cli import main

if __name__ == "__main__":
    sys.exit(main())
