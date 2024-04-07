@ echo off
cd %~dp0

if not exist .\Scripts\ (
    echo Setting up a Python virtual environment in the current location...
    echo:
    @ echo off
    python -m venv .
    echo Python virtual environment setup completed.
    echo:
)

echo Activating Python virtual environment...
echo:
@ echo off
call .\Scripts\activate
echo Python virtual environment activated...
echo:

echo Checking for required dependencies in requirements.txt...
echo:
rem We are using PyQt5 as a dummy library to check if requirements are all installed.
pip list | findstr /C:"PyQt5" > nul
if errorlevel 1 (
    echo Requirements not installed. Installing requirements...
    echo:
    @ echo off
    pip install -r requirement.txt
    echo Requirements installed.
    echo:
)

echo Setting up your private environment file...
echo:
set /p VIRUS_TOTAL_API_KEY=Enter your API key for VirusTotal (Press Enter to skip): 
set /p URL_SCAN_API_KEY=(optional) Enter your API key for URLScan (Press Enter to skip):

if "%VIRUS_TOTAL_API_KEY%"=="" (
    echo You will have to key in your VirusTotal API key in .env manually for some functionality to work.
    echo:
    echo Instructions: https://docs.virustotal.com/docs/please-give-me-an-api-key
    echo:
)
echo:

@echo off (
echo VIRUS_TOTAL_API_KEY=%VIRUS_TOTAL_API_KEY% > .env
echo URL_SCAN_API_KEY=%URL_SCAN_API_KEY% >> .env

echo URL_SCAN_API_URL=https://urlscan.io/api/v1/scan/ >> .env
echo VIRUS_TOTAL_API_DOMAIN_URL=https://www.virustotal.com/api/v3/domains/ >> .env
echo VIRUS_TOTAL_API_IP_ADDRESS_URL=https://www.virustotal.com/api/v3/ip_addresses/ >> .env
)
echo Environment file setup completed. Private environment file is saved as .env in this directory.
echo:

echo NOTE: You need to ensure that your VirusTotal API key is input correctly in .env for the program to work!
echo:

echo Ensure that the URLs for the API calls are accurate as well. Just check .env periodically to ensure that the URLs are updated!
echo:

echo Set up is completed. Running the program run.pyw now.

python run.pyw

pause > nul