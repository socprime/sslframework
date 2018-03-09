# SSL Framework
Scripts description:

ssl-framework-install.py - creates required folders, config files and domains list file for analysis
ssl-framework-report.py - launches the .sh script, parses and analyzes scan result, transforms output to CEF/LEEF/log string, sends output via Syslog or writes to file.

Requirements:
Please download the testssl.sh script from https://github.com/drwetter/testssl.sh/  and copy it to the testssl folder. 
For proxy support an openssl v 1.1 library is required.

To make meaningful analysis of script results via SIEM and integrate Qualys VM, CM or SSLLabs data please the use SSL Framework content package from:
https://my.socprime.com/en/integrations/ssl-framework-arcsight
