@echo off
start cmd /k ".\.venv\Scripts\python.exe .\server\server.py"

start cmd /k "set client_id=111111111&& .\.venv\Scripts\python.exe .\client\main.py"
start cmd /k "set client_id=222222222&& .\.venv\Scripts\python.exe .\client\main.py"

