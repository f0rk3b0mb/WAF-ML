from database import get_db, RequestLog, BlockedIP
from sqlalchemy import func

def get_total_requests():
    with next(get_db()) as db:  # Get a new database session using a context manager
        total_requests = db.query(RequestLog).count()
        return total_requests

def get_blocked_requests():
    with next(get_db()) as db:  # Get a new database session using a context manager
        blocked_requests = db.query(RequestLog).filter_by(action='Malicious request').count()
        return blocked_requests

def get_top_malicious_urls(limit=1):
    with next(get_db()) as db:  # Get a new database session using a context manager
        top_urls = (db.query(RequestLog.url, func.count(RequestLog.url).label('count'))
                    .filter(RequestLog.result == 'Malicious request')
                    .group_by(RequestLog.url)
                    .order_by(func.count(RequestLog.url).desc())
                    .limit(limit)
                    .all())
        
        return [(url, count) for url, count in top_urls]

def get_recent_attacks(limit=10):
    with next(get_db()) as db:  # Get a new database session using a context manager
        recent_attacks = (db.query(RequestLog)
                          .filter_by(action='Malicious request')
                          .order_by(RequestLog.timestamp.desc())
                          .limit(limit)
                          .all())
        
        attack_list = []
        for attack in recent_attacks:
            attack_list.append({
                'timestamp': attack.timestamp,
                'ip_address': attack.ip_address,
                'url': attack.url,
                'action': attack.action
            })
        
        return attack_list

def get_blocked_ips(limit=10):
    with next(get_db()) as db:  # Get a new database session using a context manager
        blocked_ips = (db.query(BlockedIP)
                       .order_by(BlockedIP.timestamp.desc())
                       .limit(limit)
                       .all())
        
        ip_list = []
        for entry in blocked_ips:
            ip_list.append({
                'ip_address': entry.ip_address,
                'timestamp': entry.timestamp,
                'reason': entry.reason
            })
        
        return ip_list
