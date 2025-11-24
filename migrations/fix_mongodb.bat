@echo off
REM Quick MongoDB SSL fix for Windows

echo ==========================================
echo MongoDB SSL/TLS Fix Tool
echo ==========================================
echo.
echo This will update SSL libraries and test the connection.
echo.
pause

echo.
echo Updating SSL libraries...
python -m pip install --upgrade pip
pip install --upgrade certifi pymongo cryptography
pip install python-certifi-win32

echo.
echo Testing MongoDB connection...
python migrations\test_mongo_fix.py

echo.
echo ==========================================
echo Done!
echo ==========================================
echo.
echo If the connection still fails, see:
echo   migrations\FIX_MONGODB_SSL.md
echo.
pause
