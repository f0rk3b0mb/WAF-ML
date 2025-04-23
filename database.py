from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker , relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, DateTime, func, Boolean, ForeignKey
import os
from dotenv import load_dotenv


load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./instance/requests.db")

Base = declarative_base()
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

# Define models
class Request(Base):
    __tablename__ = 'requests'
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    method = Column(String)
    ip_address = Column(String, index=True)
    headers = Column(String)
    body = Column(String)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    blocked_entry = relationship('Blocked', back_populates='request', uselist=False, cascade='all, delete')

class Blocked(Base):
    __tablename__ = 'blocked'
    id = Column(Integer,  primary_key=True ,index=True)
    request_id = Column(Integer, ForeignKey('requests.id'))
    ip_address = Column(String, index=True)
    url = Column(String, index=True)
    reason = Column(String)
    blocked_at = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String, default="blocked")
    
    request = relationship('Request', back_populates='blocked_entry')
    

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)
    is_active=Column(Boolean, default=False)
    is_approved=Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    

def add_default_records():
    session = SessionLocal()

    try:
        default_admin = User(
            username="admin", 
            password="$2b$12$UAgcgOVhk80bqRGymPLDOe2Ih839rJnKKdqDtuHqD8QqA2ALGGcmG", 
            email="admin@admin.com",
            is_admin=True,
            is_approved=True,
            is_active=True
        )
        session.add(default_admin)
        session.commit()
    except Exception as e:
        session.rollback()
        print("Error:", e)
    finally:
        session.close()


def init_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    add_default_records()
    print("Database tables created successfully!")