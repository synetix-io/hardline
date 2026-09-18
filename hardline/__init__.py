"""Hardline — RouterOS security posture scan.

Deterministic rules decide. The model only explains.
"""
__version__ = "0.1.0"


def load_dotenv() -> None:
    """Load KEY=value lines from a .env beside the project, without overriding real env vars.

    Keeps the API key on disk and out of shell history. The file is gitignored and dockerignored;
    in production the same variables come from `fly secrets`.
    """
    import os
    from pathlib import Path
    for candidate in (Path.cwd() / ".env", Path(__file__).resolve().parent.parent / ".env"):
        if not candidate.is_file():
            continue
        for line in candidate.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
        break


load_dotenv()
