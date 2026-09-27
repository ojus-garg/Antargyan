#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────
#  ANTARGYAN — 1-Click Launcher (macOS / Linux)
#  Double-click this file or run:  bash start.sh
# ──────────────────────────────────────────────────────────

set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
FLASK_PID=""
VITE_PID=""

# ─── Cleanup on exit ───
cleanup() {
    echo ""
    echo "Shutting down ANTARGYAN servers..."
    [ -n "$FLASK_PID" ] && kill "$FLASK_PID" 2>/dev/null
    [ -n "$VITE_PID" ] && kill "$VITE_PID" 2>/dev/null
    # Also kill any leftover processes on the ports
    lsof -ti:5000 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti:3000 2>/dev/null | xargs kill -9 2>/dev/null || true
    echo "All servers stopped. Goodbye!"
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

echo ""
echo "======================================================================"
echo "  ◈  ANTARGYAN // BLOCKCHAIN INTELLIGENCE ENGINE"
echo "  Starting services..."
echo "======================================================================"
echo ""

# ─── Check Python ───
PYTHON_CMD=""
if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
    PYTHON_CMD="python"
else
    echo "[ERROR] Python is not installed."
    echo "        Install it from https://www.python.org/downloads/"
    echo "        macOS: brew install python3"
    echo "        Linux: sudo apt install python3 python3-pip"
    exit 1
fi

# ─── Check Node.js ───
if ! command -v node &>/dev/null; then
    echo "[ERROR] Node.js is not installed."
    echo "        Install it from https://nodejs.org/"
    echo "        macOS: brew install node"
    echo "        Linux: sudo apt install nodejs npm"
    exit 1
fi

# ─── Check npm ───
if ! command -v npm &>/dev/null; then
    echo "[ERROR] npm is not installed."
    exit 1
fi

# ─── Install Python dependencies ───
echo "[1/4] Checking Python dependencies..."
cd "$PROJECT_DIR"
PIP_CMD="${PYTHON_CMD} -m pip"
$PIP_CMD install -q flask requests scikit-learn pandas numpy joblib networkx matplotlib 2>/dev/null || true

# ─── Install Node dependencies ───
echo "[2/4] Checking Node.js dependencies..."
cd "$PROJECT_DIR/frontend"
if [ ! -d "node_modules" ]; then
    echo "       Installing frontend packages (first run only)..."
    npm install --silent 2>/dev/null
fi

# ─── Kill any existing processes on ports 5000 & 3000 ───
echo "[3/4] Clearing ports 5000 and 3000..."
lsof -ti:5000 2>/dev/null | xargs kill -9 2>/dev/null || true
lsof -ti:3000 2>/dev/null | xargs kill -9 2>/dev/null || true
sleep 1

# ─── Start Flask backend ───
echo "[4/4] Launching servers..."
cd "$PROJECT_DIR"
$PYTHON_CMD app.py &
FLASK_PID=$!

# ─── Wait for Flask to be ready ───
echo "       Waiting for Flask backend..."
for i in $(seq 1 30); do
    if curl -s http://127.0.0.1:5000/api/health >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# ─── Start Vite frontend ───
cd "$PROJECT_DIR/frontend"
npx vite &
VITE_PID=$!

# ─── Wait for Vite to be ready ───
echo "       Waiting for Vite frontend..."
for i in $(seq 1 30); do
    if curl -s http://localhost:3000 >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# ─── Open browser ───
echo ""
echo "======================================================================"
echo "  ◈  ANTARGYAN IS LIVE!"
echo ""
echo "  Frontend : http://localhost:3000"
echo "  Backend  : http://127.0.0.1:5000"
echo ""
echo "  Press Ctrl+C to stop all servers and exit."
echo "======================================================================"
echo ""

# Open in default browser
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "http://localhost:3000"
elif command -v xdg-open &>/dev/null; then
    xdg-open "http://localhost:3000"
elif command -v wslview &>/dev/null; then
    wslview "http://localhost:3000"
fi

# Keep script alive until Ctrl+C
wait
