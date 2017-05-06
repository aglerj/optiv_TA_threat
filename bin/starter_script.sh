#!/bin/bash

#starter_script.sh

THREAT_SCRIPT_PATH="/opt/splunk/etc/apps/optiv_TA_threat/bin/optiv_threat_lists.py"
RSS_SCRIPT_PATH="/opt/splunk/etc/apps/optiv_TA_threat/bin/getalerts.py"
LOG_FOLDER1="/opt/splunk/etc/apps/optiv_TA_threat/logs"
LOG_FOLDER2="/opt/splunk/etc/apps/optiv_TA_threat/bin"
PYTHON="/opt/splunk/bin/splunk cmd python"
MAX_DAYS_TO_KEEP=2

echo "[*] My python exec command is: $PYTHON"
echo "[*] My python threat list script is: $THREAT_SCRIPT_PATH"
echo "[*] My python get alerts script is: $RSS_SCRIPT_PATH"
echo "[*] My log folder is: $LOG_FOLDER1"
echo "[*] Keep log files for: $MAX_DAYS_TO_KEEP days."

echo "[*] Executing threat list script."
$PYTHON $THREAT_SCRIPT_PATH
echo "[*] Executing get alerts script."
$PYTHON $RSS_SCRIPT_PATH

echo "Python scripts are done, looking for log files to clear."
find $LOG_FOLDER1/optiv*.txt -type f -mtime +$MAX_DAYS_TO_KEEP -exec rm -f {} \;
find $LOG_FOLDER1/optiv_*.log -type f -mtime +$MAX_DAYS_TO_KEEP -exec rm -f {} \;
find $LOG_FOLDER2/getalerts*.log -type f -mtime +$MAX_DAYS_TO_KEEP -exec rm -f {} \;
