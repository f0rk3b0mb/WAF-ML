from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from datetime import datetime

# Define the base class for the models
Base = declarative_base()

# Define the Request model to store request data
class Request(Base):
    __tablename__ = 'requests'

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    method = Column(String)
    ip_address = Column(String, nullable=True, index=True)
    headers = Column(String)
    body = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

# Define the Blocked model to store blocked IPs
class Blocked(Base):
    __tablename__ = 'blocked'

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, nullable=True, index=True)
    url = Column(String, nullable=True, index=True)
    reason = Column(String, nullable=True)  # Reason for blocking
    blocked_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="blocked")

# Define the User model with only username, email, and password
class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(255), nullable=False)

# Database URL (SQLite in this case)
DATABASE_URL = "sqlite+aiosqlite:///./instance/requests.db"  # Using a file-based SQLite database

# Create an asynchronous engine (for async database operations)
engine = create_async_engine(DATABASE_URL, echo=True)

# Create a session maker for async sessions
SessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)




async def add_default_records():
    async with SessionLocal() as session:
         # Create default users
        default_admin = User(username="admin", password="scrypt:32768:8:1$7Cz857dN4cjl58TX$a36a634311861488eb48d18f3d5c095c0cd70d5dc4f527e17579251456f3beb9480743da4adb48cb1952913860a5c0528d8f6240cb8b98d4557716774b6abce4", email="admin@admin.com")
        #default_user = User(username="test", password=, email="test@test.com")
        
        session.add(default_admin)
        #session.add(default_user)

# Function to initialize the database (create tables)
async def init_db():
    add_default_records()
    # Create tables if they don't exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
