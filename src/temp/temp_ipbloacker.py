import subprocess

li = ["192.168.1.1","192.168.1.2","192.168.1.3","192.168.1.4"]

def block_ip(ip):
    # PowerShell command to check if the firewall rule exists
    check_command = f'Get-NetFirewallRule -DisplayName "Block Remote {ip}"'

    # Execute the check command to see if the rule already exists
    check_process = subprocess.Popen(
        ['powershell', '-Command', check_command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    check_stdout, check_stderr = check_process.communicate()

    if check_process.returncode == 0 and check_stdout.strip():
        # The firewall rule already exists
        print(f'Firewall rule for ip {ip} already exists. No action taken.')
    else:
        # The firewall rule does not exist, proceed to add it
        add_command = f'New-NetFirewallRule -RemoteAddress {ip} -DisplayName "Block Remote {ip}" -Direction inbound -Action Block'
        add_process = subprocess.Popen(
            ['powershell', '-Command', add_command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        add_stdout, add_stderr = add_process.communicate()

        if add_process.returncode == 0:
            print(f'CONSOLE_LOG ip {ip} blocked successfully on Windows.')
    
        else:
            print('Error occurred while executing the command:')
            print(add_stderr.decode().strip())

for ip in li:
    block_ip(ip)
