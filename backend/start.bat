@echo off
echo Starting IoMT SOC Backend...
cd /d %~dp0
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
pause
