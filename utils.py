import subprocess

def block_ip(ip):
    try:
        # Blocking the IP using iptables
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
        print(f"Blocked IP: {ip}")
    except Exception as e:
        print(f"Failed to block IP {ip}: {e}")



def unblock_ip(ip):
    try:
        # Unblocking the IP using iptables
        subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
        print(f"Unblocked IP: {ip}")
    except Exception as e:
        print(f"Failed to unblock IP {ip}: {e}")