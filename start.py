"""
ANTARGYAN — Universal 1-Click Launcher (Cross-Platform)
Works on Windows, macOS, and Linux.

Usage:
    python start.py
"""

import os
import sys
import time
import signal
import socket
import webbrowser
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = ROOT_DIR / "frontend"

def is_port_in_use(port: int) -> bool:
    """Check if a local port is already occupied."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0

def kill_port(port: int):
    """Attempt to terminate process bound to a port."""
    if not is_port_in_use(port):
        return
    if sys.platform == "win32":
        try:
            out = subprocess.check_output(f'netstat -aon | findstr ":{port} "', shell=True, text=True)
            for line in out.strip().splitlines():
                if "LISTENING" in line:
                    pid = line.strip().split()[-1]
                    subprocess.run(f"taskkill /PID {pid} /F", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    else:
        try:
            subprocess.run(f"lsof -ti:{port} | xargs kill -9", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

def main():
    print("\n" + "=" * 70)
    print("  ◈  ANTARGYAN // BLOCKCHAIN FORENSIC INTELLIGENCE SUITE")
    print("  Initializing unified multi-tier launch...")
    print("=" * 70 + "\n")

    # 1. Clean ports
    print("[1/4] Ensuring clean ports 5000 and 3000...")
    kill_port(5000)
    kill_port(3000)
    time.sleep(0.5)

    # 2. Check dependencies
    print("[2/4] Verifying node modules...")
    if not (FRONTEND_DIR / "node_modules").exists():
        print("      Installing frontend dependencies (first-time setup)...")
        npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
        subprocess.run([npm_cmd, "install"], cwd=FRONTEND_DIR)

    # 3. Start Flask Backend
    print("[3/4] Starting Flask API engine (Port 5000)...")
    backend_proc = subprocess.Popen(
        [sys.executable, str(ROOT_DIR / "app.py")],
        cwd=ROOT_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # Wait for backend to bind port 5000
    for _ in range(30):
        if is_port_in_use(5000):
            break
        time.sleep(0.3)

    # 4. Start Vite Frontend
    print("[4/4] Starting Vite UI server (Port 3000)...")
    npx_cmd = "npx.cmd" if sys.platform == "win32" else "npx"
    frontend_proc = subprocess.Popen(
        [npx_cmd, "vite"],
        cwd=FRONTEND_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # Wait for frontend to bind port 3000
    for _ in range(30):
        if is_port_in_use(3000):
            break
        time.sleep(0.3)

    print("\n" + "=" * 70)
    print("  ◈  ANTARGYAN IS RUNNING AND READY!")
    print("  Frontend UI : http://localhost:3000")
    print("  Backend API : http://127.0.0.1:5000")
    print("  Press Ctrl+C anytime in this window to stop all services.")
    print("=" * 70 + "\n")

    # Automatically launch default web browser
    webbrowser.open("http://localhost:3000")

    def handle_exit(sig=None, frame=None):
        print("\nStopping ANTARGYAN services...")
        backend_proc.terminate()
        frontend_proc.terminate()
        try:
            backend_proc.wait(timeout=2)
            frontend_proc.wait(timeout=2)
        except Exception:
            backend_proc.kill()
            frontend_proc.kill()
        kill_port(5000)
        kill_port(3000)
        print("All servers stopped successfully. Goodbye!")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    try:
        while True:
            time.sleep(1)
            # Check if any process died unexpectedly
            if backend_proc.poll() is not None or frontend_proc.poll() is not None:
                print("\n[!] One of the servers terminated. Shutting down.")
                handle_exit()
    except KeyboardInterrupt:
        handle_exit()

if __name__ == "__main__":
    main()
