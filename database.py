from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, DateTime, func

DATABASE_URL = "sqlite:///./instance/requests.db"

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

class Blocked(Base):
    __tablename__ = 'blocked'
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, index=True)
    url = Column(String, index=True)
    reason = Column(String)
    blocked_at = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String, default="blocked")

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(255), nullable=False)

async def add_default_records():
    async with SessionLocal() as session:
         # Create default users
        default_admin = User(username="admin", password="scrypt:32768:8:1$7Cz857dN4cjl58TX$a36a634311861488eb48d18f3d5c095c0cd70d5dc4f527e17579251456f3beb9480743da4adb48cb1952913860a5c0528d8f6240cb8b98d4557716774b6abce4", email="admin@admin.com")
        #default_user = User(username="test", password=, email="test@test.com")
        
        session.add(default_admin)
        #session.add(default_user)
    

def add_default_records():
    session = SessionLocal()
    try:
        default_admin = User(username="admin", password="scrypt:32768:8:1$7Cz857dN4cjl58TX$a36a634311861488eb48d18f3d5c095c0cd70d5dc4f527e17579251456f3beb9480743da4adb48cb1952913860a5c0528d8f6240cb8b98d4557716774b6abce4", email="admin@admin.com")
        session.add(default_admin)
        session.commit()
    except Exception as e:
        session.rollback()
        print("Error:", e)
    finally:
        session.close()


def init_db():
    add_default_records()
    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully!")