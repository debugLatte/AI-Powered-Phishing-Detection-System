@echo off
REM PhishGuard Quick Start - Windows

echo.
echo ============================================================
echo     PhishGuard - AI-Powered Phishing Detection System
echo ============================================================
echo.

REM Check if running from correct directory
if not exist "backend\api.py" (
    echo Error: Please run this script from the phishing-detector root directory
    pause
    exit /b 1
)

echo Starting PhishGuard components...
echo.

REM Terminal 1: Start Backend API
echo [1/2] Starting Backend API on http://localhost:8000
start cmd /k "cd backend && python api.py"
timeout /t 3 /nobreak

REM Terminal 2: Start Frontend Server
echo [2/2] Starting Frontend on http://localhost:8080
start cmd /k "cd frontend && python server.py"

echo.
echo ============================================================
echo Ready! Open your browser:
echo   Frontend: http://localhost:8080
echo   API: http://localhost:8000/health
echo ============================================================
echo.
pause
