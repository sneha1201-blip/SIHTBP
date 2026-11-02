#!/usr/bin/env python3
"""Zero-Friction Full-Stack Platform Orchestrator.

Smart India Hackathon (SIH Problem Statement ID: 26106)
AICTE Cyber Security Cell:
"AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform"

Performs in sequence:
1. Environment & runtime validation (Python 3.10+, Node.js 18+).
2. Database schema initialization & seeding of the 5 realistic forensic cases.
3. Launches FastAPI ASGI backend on http://127.0.0.1:8000.
4. Launches Next.js SOC Analyst Dashboard on http://localhost:3000.
5. Automatically opens the user's default browser to http://localhost:3000.
6. Handles graceful shutdown of all processes upon Ctrl+C.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
BACKEND_DIR = PROJECT_ROOT / "backend"

# Terminal Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_header():
    print(f"""
{CYAN}{BOLD}================================================================================
   AICTE CYBER SECURITY CELL | SMART INDIA HACKATHON 2026 (SIH ID: 26106)
   AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence
   ZERO-FRICTION FULL-STACK ORCHESTRATOR
================================================================================{RESET}
""")


def find_executable(name: str, fallback_paths: list[str]) -> str:
    """Locate an executable in standard PATH or known local install locations."""
    # Check standard PATH
    from shutil import which
    found = which(name)
    if found:
        return found

    # Check fallback paths (e.g. Windows specific user programs)
    for p in fallback_paths:
        cand = Path(p)
        if cand.exists() and cand.is_file():
            return str(cand)

    return name


def get_node_and_npm() -> tuple[str, str]:
    """Find node and npm executables, checking Windows AppData paths if needed."""
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    win_node_dir = Path(local_app_data) / "Programs" / "nodejs" if local_app_data else None

    node_fallbacks = []
    npm_fallbacks = []

    if win_node_dir and win_node_dir.exists():
        node_fallbacks.append(str(win_node_dir / "node.exe"))
        npm_fallbacks.append(str(win_node_dir / "npm.cmd"))

    node_bin = find_executable("node", node_fallbacks)
    npm_bin = find_executable("npm", npm_fallbacks)

    return node_bin, npm_bin


def initialize_database():
    """Initialize database and seed the 5 forensic test cases."""
    print(f"{YELLOW}[*] Initializing SQLite database & seeding 5 forensic test cases...{RESET}")
    sys.path.insert(0, str(PROJECT_ROOT))
    try:
        from backend.app.database.init_db import init_db_and_verify
    except ImportError:
        import asyncio
        from backend.app.database.init_db import initialize_and_verify
        init_db_and_verify = lambda **kw: asyncio.run(initialize_and_verify(**kw))

    success = init_db_and_verify(reset=True)
    if not success:
        print(f"{RED}[!] Database initialization failed. Exiting.{RESET}")
        sys.exit(1)
    print(f"{GREEN}[+] Database schemas created & 5 forensic seed cases loaded.{RESET}\n")


def wait_for_service(url: str, name: str, timeout_sec: int = 25) -> bool:
    """Poll an HTTP URL until it returns 200 or times out."""
    start = time.time()
    while time.time() - start < timeout_sec:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "HealthCheck/1.0"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status in (200, 201, 304):
                    return True
        except Exception:
            pass
        time.sleep(0.6)
    return False


def main():
    print_header()

    # Step 1: Detect runtime tools
    node_bin, npm_bin = get_node_and_npm()
    print(f"[*] Python interpreter : {sys.executable}")
    print(f"[*] Node.js runtime    : {node_bin}")
    print(f"[*] Package manager    : {npm_bin}\n")

    # Ensure node directory is in PATH for child processes
    node_dir = str(Path(node_bin).parent)
    if node_dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = f"{node_dir}{os.pathsep}{os.environ.get('PATH', '')}"

    # Step 2: Initialize Database & Vault
    initialize_database()

    processes: list[subprocess.Popen] = []

    def shutdown(signum=None, frame=None):
        print(f"\n{YELLOW}[*] Gracefully terminating platform services...{RESET}")
        for p in processes:
            try:
                if p.poll() is None:
                    p.terminate()
                    p.wait(timeout=3)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        print(f"{GREEN}[+] AICTE Forensic Platform terminated cleanly. Goodbye!{RESET}")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Step 3: Launch FastAPI Backend (Port 8000)
    print(f"{YELLOW}[*] Launching FastAPI Backend on http://127.0.0.1:8000 ...{RESET}")
    backend_cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "backend.app.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        "8000",
    ]
    backend_proc = subprocess.Popen(
        backend_cmd,
        cwd=str(PROJECT_ROOT),
        env=os.environ.copy(),
    )
    processes.append(backend_proc)

    # Wait for backend readiness
    backend_ready = wait_for_service("http://127.0.0.1:8000/", "FastAPI Backend", timeout_sec=20)
    if backend_ready:
        print(f"{GREEN}[+] FastAPI Backend is healthy and listening on http://127.0.0.1:8000{RESET}")
        print(f"    - Interactive Docs: http://127.0.0.1:8000/docs")
    else:
        print(f"{RED}[!] Warning: Backend took longer than expected to report ready.{RESET}")

    # Step 4: Launch Next.js Frontend (Port 3000)
    print(f"\n{YELLOW}[*] Launching Next.js SOC Dashboard on http://localhost:3000 ...{RESET}")
    frontend_cmd = [npm_bin, "run", "dev"]
    frontend_proc = subprocess.Popen(
        frontend_cmd,
        cwd=str(FRONTEND_DIR),
        env=os.environ.copy(),
        shell=(os.name == "nt"),
    )
    processes.append(frontend_proc)

    # Wait for frontend readiness
    frontend_ready = wait_for_service("http://localhost:3000/", "Next.js Dashboard", timeout_sec=30)
    if frontend_ready:
        print(f"{GREEN}[+] Next.js SOC Dashboard is ready on http://localhost:3000{RESET}")
    else:
        print(f"{YELLOW}[*] Frontend is compiling; will be reachable shortly at http://localhost:3000{RESET}")

    # Step 5: Automatically open default browser
    print(f"\n{CYAN}{BOLD}[+] Opening browser to http://localhost:3000 ...{RESET}")
    try:
        webbrowser.open("http://localhost:3000")
    except Exception:
        pass

    print(f"\n{GREEN}{BOLD}================================================================================")
    print("   AICTE CYBER SECURITY CELL FORENSIC PLATFORM IS FULLY OPERATIONAL")
    print("   - Dashboard   : http://localhost:3000")
    print("   - REST API    : http://127.0.0.1:8000/api/v1")
    print("   - Swagger Docs: http://127.0.0.1:8000/docs")
    print("   Press Ctrl+C to stop all servers and exit.")
    print(f"================================================================================{RESET}\n")

    # Monitor processes until user terminates
    try:
        while True:
            time.sleep(1)
            for p in processes:
                if p.poll() is not None:
                    print(f"{RED}[!] A platform process exited with code {p.returncode}.{RESET}")
                    shutdown()
    except KeyboardInterrupt:
        shutdown()


if __name__ == "__main__":
    main()

