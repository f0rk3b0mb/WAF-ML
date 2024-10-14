from sqlalchemy import create_engine, Column, Integer, String, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime
import os

# Database connection
DATABASE_URL = 'mysql+mysqlconnector://root:57071246@localhost/test'
#DATABASE_URL = "mysql://user:password@db:3306/mydb"

engine = create_engine(DATABASE_URL, echo=True)
Base = declarative_base()
Session = sessionmaker(bind=engine)

# Define the BlockedIP model
class BlockedIP(Base):
    __tablename__ = 'blocked_ips'
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(50), nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"<BlockedIP {self.ip_address}>"

# Define the RequestLog model
class RequestLog(Base):
    __tablename__ = 'request_logs'
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(50), nullable=False)
    action = Column(String(50))
    url = Column(String(50))
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    result = Column(String(50))  # Normal or Malicious

    def __repr__(self):
        return f"<RequestLog {self.url} from {self.ip_address}>"

# Define the User model
class User(Base):
    __tablename__ = 'users'  # Ensure the table name is defined
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(200), nullable=False)
    email = Column(String(50))
    date_registered = Column(DateTime, default=datetime.datetime.utcnow)  # Change to DateTime for consistency

    def __repr__(self):
        return f"<User {self.username}>"

# Create the database and tables
def init_db():
    Base.metadata.create_all(engine)
    print("WAF database initialized.")

# Function to add a blocked IP
def add_blocked_ip(ip):
    session = Session()
    try:
        new_block = BlockedIP(ip_address=ip)
        session.add(new_block)
        session.commit()
        print(f"Blocked IP {ip} added to the database.")
    except Exception as e:
        session.rollback()  # Rollback in case of error
        print(f"Error adding blocked IP {ip}: {e}")
    finally:
        session.close()

def log_request(ip, url, action):
    # Log requests to a file instead of the database
    log_file_path = "logs/access_logs.csv"

    # Ensure logs directory and file exist
    os.makedirs("logs", exist_ok=True)
    if not os.path.exists(log_file_path):
        with open(log_file_path, "w") as f:
            f.write("timestamp,ip,url,action\n")  # Write header if new file

    # Write log entry to file
    try:
        log = f"{datetime.datetime.now()}, {ip}, {url}, {action}\n"
        with open(log_file_path, "a") as f:
            f.write(log)
            print(log.strip())
    except Exception as e:
        print(f"Error writing to log file: {e}")

    # Log requests to the database
    session = Session()
    try:
        new_log = RequestLog(ip_address=ip, url=url, action=action)
        session.add(new_log)

        # Purge old records if more than 50
        count = session.query(func.count(RequestLog.id)).scalar()  # Assuming id is the primary key
        if count > 50:
            oldest_logs = session.query(RequestLog).order_by(RequestLog.timestamp).limit(count - 50).all()
            for log in oldest_logs:
                session.delete(log)

        session.commit()
        print(f"Request logged in database: {url} from {ip}")
    except Exception as e:
        session.rollback()  # Rollback in case of error
        print(f"Error logging request {url} from {ip}: {e}")
    finally:
        session.close()



def add_default_record():
    session = Session()
    try:
        # Create default user records
        default_admin = User(username="admin", password="$2b$12$SUy7HGNzEen/MY.E9rKJpeqz9m5QldDSR0nWusFsolwORG51u98za", email="admin@admin.com")
        session.add(default_admin)
        
        default_user = User(username="test", password="$2b$12$SUy7HGNzEen/MY.E9rKJpeqz9m5QldDSR0nWusFsolwORG51u98za", email="test@test.com")
        session.add(default_user)
        
        session.commit()
        print("Default users added to the database.")
    except Exception as e:
        session.rollback()  # Rollback in case of error
        print(f"Error adding default users: {e}")
    finally:
        session.close()


if __name__ == '__main__':
    #Base.metadata.drop_all(engine)
    init_db()
    add_default_record() 
