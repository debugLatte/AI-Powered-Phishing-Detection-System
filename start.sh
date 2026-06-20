#!/bin/bash

# PhishGuard Quick Start - Linux/Mac

echo ""
echo "============================================================"
echo "     PhishGuard - AI-Powered Phishing Detection System"
echo "============================================================"
echo ""

# Check if running from correct directory
if [ ! -f "backend/api.py" ]; then
    echo "Error: Please run this script from the phishing-detector root directory"
    exit 1
fi

echo "Starting PhishGuard components..."
echo ""

# Terminal 1: Start Backend API
echo "[1/2] Starting Backend API on http://localhost:8000"
cd backend && python api.py &
BACKEND_PID=$!
sleep 2

# Terminal 2: Start Frontend Server
echo "[2/2] Starting Frontend on http://localhost:8080"
cd ../frontend && python server.py &
FRONTEND_PID=$!

echo ""
echo "============================================================"
echo "Ready! Open your browser:"
echo "   Frontend: http://localhost:8080"
echo "   API: http://localhost:8000/health"
echo "============================================================"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Wait for both processes
wait
