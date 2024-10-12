import subprocess
from database import BlockedIP, RequestLog, session
from database import add_blocked_ip
from sqlalchemy import func 



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



def get_total_requests():
    return RequestLog.query.count()


def get_blocked_requests():
    return RequestLog.query.filter_by(action='Blocked').count()

def get_top_malicious_urls(session, limit=5):
    # Get the top 'limit' malicious URLs by frequency
    top_urls = (session.query(RequestLog.url, func.count(RequestLog.url).label('count'))
                .filter(RequestLog.result == 'Malicious request')  # Adjusting the filter condition
                .group_by(RequestLog.url)
                .order_by(func.count(RequestLog.url).desc())  # Order by count in descending order
                .limit(limit)
                .all())
    
    return [(url, count) for url, count in top_urls]


def get_recent_attacks(limit=10):
    recent_attacks = (RequestLog.query.filter_by(action='Blocked')
                      .order_by(RequestLog.timestamp.desc())
                      .limit(limit)
                      .all())
    attack_list = []
    for attack in recent_attacks:
        attack_list.append({
            'timestamp': attack.timestamp,
            'source_ip': attack.source_ip,
            'url': attack.url,
            'attack_type': attack.attack_type,
            'action': attack.action
        })
    
    return attack_list



def get_blocked_ips(limit=10):
    blocked_ips = BlockedIP.query.order_by(BlockedIP.timestamp.desc()).limit(limit).all()
    
    # Convert to list of dictionaries for front-end
    ip_list = []
    for entry in blocked_ips:
        ip_list.append({
            'ip_address': entry.ip_address,
            'timestamp': entry.timestamp,
            'reason': entry.reason
        })
    
    return ip_list