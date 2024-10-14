import os
import matplotlib.pyplot as plt
import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from io import BytesIO
from flask import send_file
from database import RequestLog, BlockedIP

# Create a new SQLAlchemy session
engine = create_engine('mysql+mysqlconnector://root:57071246@localhost/test')
Session = sessionmaker(bind=engine)

def fetch_logs():
    session = Session()
    try:
        logs = session.query(RequestLog).all()
        return logs
    except Exception as e:
        print(f"Error fetching logs: {e}")
        return []
    finally:
        session.close()

def visualize_logs(filter_type):
    logs = fetch_logs()
    
    if not logs:
        return None

    # Convert logs to a DataFrame
    data = {
        "timestamp": [log.timestamp for log in logs],
        "ip_address": [log.ip_address for log in logs],
        "url": [log.url for log in logs],
        "action": [log.action for log in logs],
    }
    df = pd.DataFrame(data)

    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Extract only the date part
    df['date'] = df['timestamp'].dt.date
    
    # Convert the 'date' column to datetime and set it as the index
    df['date'] = pd.to_datetime(df['date'])
    df.set_index('timestamp', inplace=True)  # Set timestamp as index for resampling

    # Group counts based on filter
    if filter_type == 'hour':
        counts = df.resample('H').count()
    elif filter_type == 'day':
        counts = df.resample('D').count()
    elif filter_type == 'week':
        counts = df.resample('W').count()
    else:
        print("Invalid filter type. Use 'hour', 'day', or 'week'.")
        return None

    # Prepare a plot for the selected access counts
    plt.figure(figsize=(10, 6))
    counts['url'].plot(kind='bar', color='skyblue')
    plt.title(f'{filter_type.capitalize()} Access Counts by URL')
    plt.xlabel('Date')
    plt.ylabel('Access Counts')
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    # Save plot to a BytesIO object
    img = BytesIO()
    plt.savefig(img, format='png')
    plt.close()  # Close the figure to free memory
    img.seek(0)
    return img

def fetch_blocked_ips():
    session = Session()
    try:
        blocked_ips = session.query(BlockedIP).all()
        return blocked_ips
    except Exception as e:
        print(f"Error fetching blocked IPs: {e}")
        return []
    finally:
        session.close()

def visualize_blocked_ips(filter_type):
    blocked_ips = fetch_blocked_ips()
    
    if not blocked_ips:
        return None

    # Convert blocked IPs to a DataFrame
    data = {
        "timestamp": [ip.timestamp for ip in blocked_ips],
        "ip_address": [ip.ip_address for ip in blocked_ips],
    }
    df = pd.DataFrame(data)

    # Group counts based on filter
    if filter_type == 'hour':
        counts = df.groupby(['ip_address', df['timestamp'].dt.hour]).size().unstack(fill_value=0)
        counts.index.name = 'IP Address'
        counts.columns.name = 'Hour'
    elif filter_type == 'day':
        counts = df.groupby(['ip_address', df['timestamp'].dt.date]).size().unstack(fill_value=0)
        counts.index.name = 'IP Address'
        counts.columns.name = 'Date'
    elif filter_type == 'week':
        counts = df.groupby(['ip_address', df['timestamp'].dt.isocalendar().week]).size().unstack(fill_value=0)
        counts.index.name = 'IP Address'
        counts.columns.name = 'Week'
    else:
        print("Invalid filter type. Use 'hour', 'day', or 'week'.")
        return None

    # Prepare a plot for the selected blocked IPs
    counts.plot(kind='bar', stacked=True, figsize=(10, 6), color='red')
    plt.title(f'{filter_type.capitalize()} Blocked IPs by IP Address')
    plt.xlabel('IP Address')
    plt.ylabel('Number of Blocked IPs')
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    # Save plot to a BytesIO object
    img = BytesIO()
    plt.savefig(img, format='png')
    plt.close()  # Close the figure to free memory
    img.seek(0)
    return img
