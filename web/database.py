from sqlalchemy import create_engine, Column, Integer, String, DateTime, Date
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import datetime

# Define the database URL
DATABASE_URL = 'mysql+mysqlconnector://root:57071246@localhost/test'

# Create a new SQLAlchemy engine
engine = create_engine(DATABASE_URL, echo=True)

# Define the base class for your models
Base = declarative_base()

# Define your models here

class User(Base):
    __tablename__ = 'users'  # Name of the table in the database

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(100), unique=True, index=True)
    password = Column(String(1000))  # Assuming hashed passwords
    date_registered = Column(Date)  # For OTP verification


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
    url = Column(String(50), nullable=False)
    action = Column(String(50), nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    result = Column(String(50), nullable=False)  # Normal or Malicious

    def __repr__(self):
        return f"<RequestLog {self.url} from {self.ip_address}>"

# Create a configured "Session" class
SessionLocal = sessionmaker(bind=engine)

# Create a session to use in the application
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Create tables in the database
Base.metadata.create_all(bind=engine)
