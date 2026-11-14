@echo off
title PSYCHE AI — Legion 5 Pro Sovereign Workbench
cd /d "C:\Users\Sidharth V Kurup\.gemini\antigravity\scratch\PSYCHE-AI"
set PSYCHE_ENABLE_LLAMA=1
python launch_psyche.py
if errorlevel 1 (
    echo.
    echo PSYCHE AI exited with an error. Check output above.
    pause
)
