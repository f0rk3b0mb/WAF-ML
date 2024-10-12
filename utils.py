import subprocess
from database import add_blocked_ip



def block_ip(ip):
    try:
        # Blocking the IP using iptables
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
        print(f"Blocked IP: {ip}")

        # Log the blocked IP to the database
        add_blocked_ip(ip)

        print(f"Logged blocked IP: {ip} to the database")

    except Exception as e:
        print(f"Failed to block IP {ip}: {e}")




def unblock_ip(ip):
    try:
        # Unblocking the IP using iptables
        subprocess.run(['sudo','iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
        print(f"Unblocked IP: {ip}")
    except Exception as e:
        print(f"Failed to unblock IP {ip}: {e}")