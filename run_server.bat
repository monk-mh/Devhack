@echo off
title PrivacyShield AI - FastAPI Backend Server
echo Starting FastAPI Backend Server on port 8000...
py -m uvicorn server:app --host 127.0.0.1 --port 8000 --reload
pause
