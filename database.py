from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime

# Database connection
DATABASE_URL = 'sqlite:///dbs/waf.db'  # Use your desired database URL
engine = create_engine(DATABASE_URL, echo=True)
Base = declarative_base()

Session = sessionmaker(bind=engine)

# Create a new session
session = Session()

# Define the BlockedIP model
class BlockedIP(Base):
    __tablename__ = 'blocked_ips'
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(50), nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"<BlockedIP {self.ip_address}>"
    


class RequestLog(Base):
    __tablename__ = 'request_logs'
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(50), nullable=False)
    url = Column(String(50), nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    result = Column(String(50), nullable=False)  # Normal or Malicious

    def __repr__(self):
        return f"<RequestLog {self.url} from {self.ip_address}>"

# Create the database and tables
def init_db():
    Base.metadata.create_all(engine)
    print("WAF database initialized.")

# Function to add a blocked IP
def add_blocked_ip(ip):
    session = Session()
    new_block = BlockedIP(ip_address=ip)
    session.add(new_block)
    session.commit()
    session.close()
    print(f"Blocked IP {ip} added to the database.")

def log_request(ip, url):
    session = Session()
    new_log = RequestLog(ip_address=ip, url=url)
    session.add(new_log)
    session.commit()
    session.close()
    print(f"Request logged: {url} from {ip}")

if __name__ == '__main__':
    init_db()  # Initialize the database when the script runs
