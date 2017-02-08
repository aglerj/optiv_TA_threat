
@echo off

echo [*] Starting python threat list script. 
"C:\Program Files\Splunk\bin\splunk.exe" cmd python "c:\program files\splunk\etc\apps\optiv_threat_intel\bin\optiv_threat_lists.py"
echo [*] Starting python get alerts script.
"C:\Program Files\Splunk\bin\splunk.exe" cmd python "c:\program files\splunk\etc\apps\optiv_threat_intel\bin\getalerts.py"
echo [*] Looking for old log files to clear.
forfiles -p "c:\program files\splunk\var\log\splunk" -s -m optiv_*.log -d -3 -c "cmd /c del @path"
forfiles -p "c:\program files\splunk\etc\apps\optiv_threat_intel\bin" -s -m getalerts*.log -d -3 -c "cmd /c del @path"

