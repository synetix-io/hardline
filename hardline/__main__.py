"""`python -m hardline` and the packaged executables land here."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
