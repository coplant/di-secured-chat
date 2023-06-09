from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, TIMESTAMP, ForeignKey
from sqlalchemy.orm import relationship
from src.database import Base


class Role(Base):
    __tablename__ = "roles"
    id: int = Column(Integer, primary_key=True)
    name: str = Column(String, nullable=False)


class User(Base):
    __tablename__ = "users"
    id: int = Column(Integer, primary_key=True)
    uid: str = Column(String, unique=True, nullable=False)
    name: str = Column(String, nullable=False)
    username: str = Column(String, unique=True, nullable=False)
    public_key: str = Column(String, nullable=True)
    hashed_password: str = Column(String(length=1024), nullable=False)
    has_changed_password: bool = Column(Boolean, default=False)
    hashed_token: str = Column(String(length=1024))
    logged_at: datetime = Column(TIMESTAMP, default=datetime.utcnow)
    created_at: datetime = Column(TIMESTAMP, default=datetime.utcnow)
    changed_at: datetime = Column(TIMESTAMP, default=datetime.utcnow)
    role_id: int = Column(Integer, ForeignKey("roles.id"))
    chats = relationship("Chat", secondary="chatsusers", lazy="selectin", back_populates="users")
    messages = relationship("Message", back_populates="author")
    is_active: bool = Column(Boolean, default=True, nullable=True)


class Log(Base):
    __tablename__ = "logs"
    id: int = Column(Integer, primary_key=True)
    timestamp: datetime = Column(TIMESTAMP, default=datetime.utcnow)
    user_id: int = Column(Integer, ForeignKey("users.id"))
    details: str = Column(String, nullable=True)
    action: str = Column(String, nullable=False)
