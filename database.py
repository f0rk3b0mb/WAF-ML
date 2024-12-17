from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
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
    headers = Column(Text)
    body = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)

class Blocked(Base):
    __tablename__ = 'blocked'

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, nullable=True, index=True)
    url = Column(String, nullable=True, index=True)
    reason = Column(Text, nullable=True)  # Reason for blocking
    blocked_at = Column(DateTime, default=datetime.utcnow) 
    status = Column(String, default="blocked")

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

# Function to initialize the database (create tables)
async def init_db():
    # Create tables if they don't exist
    async with engine.begin() as conn:
        # Create all the tables in the database
        await conn.run_sync(Base.metadata.create_all)
