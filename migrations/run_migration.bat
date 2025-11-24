@echo off
REM Helper script to run the user key migration (Windows)

echo ==========================================
echo User Key Migration Helper
echo ==========================================
echo.

REM Check if dry-run flag is provided
if "%1"=="--dry-run" (
    echo Running in DRY RUN mode (no changes will be made^)
    echo.
    python migrations\002_migrate_existing_users_keys.py --dry-run
) else (
    echo WARNING: This will modify your database!
    echo.
    echo A backup will be created automatically, but please ensure you have
    echo additional backups before proceeding.
    echo.
    set /p confirm="Do you want to continue? (yes/no): "
    
    if /i "%confirm%"=="yes" (
        echo.
        echo Starting migration...
        python migrations\002_migrate_existing_users_keys.py
    ) else (
        echo Migration cancelled.
        exit /b 0
    )
)
