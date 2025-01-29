@echo off

echo {"is_registered": false} >  client\resources\111111111-state.json
echo {"is_registered": false} >  client\resources\222222222-state.json

start cmd /k ".\.venv\Scripts\python.exe .\server\server.py"

start cmd /k "set client_id=111111111&& .\.venv\Scripts\python.exe .\client\main.py"
start cmd /k "set client_id=222222222&& .\.venv\Scripts\python.exe .\client\main.py"

