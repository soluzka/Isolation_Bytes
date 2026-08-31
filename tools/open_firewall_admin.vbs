Set UAC = CreateObject("Shell.Application")
UAC.ShellExecute "C:\Users\bpier\OneDrive\Documents\antivirus-yara-rules-c\antivirus-yara-rules-c\tools\open_firewall.bat", "", "", "runas", 1
