@echo off
setlocal
where python >nul 2>nul || (echo Python not found & exit /b 1)
python -m venv .venv
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -m pip install --upgrade pip
  if exist requirements.txt (
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
  )
  echo Done. Activate with: .venv\Scripts\activate.bat
) else (
  echo Failed to create venv
  exit /b 1
)
