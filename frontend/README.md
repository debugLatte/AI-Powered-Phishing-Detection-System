# PhishGuard Frontend

A simple, clean web interface to test the phishing detection API.

## Quick Start

### Option 1: Run the Built-in Server (Recommended)

```bash
# From the frontend folder
cd frontend
python server.py
```

Then open your browser to **http://localhost:8080**

### Option 2: Use Python's Built-in Server

```bash
cd frontend
python -m http.server 8080
```

Then open **http://localhost:8080**

### Option 3: Use Node.js http-server (if installed)

```bash
cd frontend
npx http-server -p 8080
```

## Features

- **URL Scanner** - Analyze URLs for phishing indicators
- **Email Scanner** - Analyze email text for phishing signals
- **API Status** - Check if backend API is running and models are loaded
- **Real-time Results** - Get instant feedback with risk scores and explanations

## Before Testing

Make sure the backend API is running:

```bash
cd backend
python api.py
```

The API should be running on **http://localhost:8000**

## Testing Examples

### Test URL (Phishing)
```
https://amaz0n-login-security.xyz
```

### Test Email (Phishing)
```
Your account will be SUSPENDED immediately! Click here NOW to verify password!
```

### Test URL (Safe)
```
https://github.com
```

## Troubleshooting

**Error: "Connection Error"**
- Make sure backend API is running: `python backend/api.py`
- Check that API is on port 8000

**CORS Issues**
- The API has CORS enabled for all origins (by default)
- In production, restrict this to your domain

## File Structure

```
frontend/
├── index.html      # Main HTML
├── styles.css      # Styling
├── script.js       # Frontend logic
├── server.py       # Simple HTTP server
└── README.md       # This file
```
