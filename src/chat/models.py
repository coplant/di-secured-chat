from datetime import datetime

from sqlalchemy import Column, Integer, String, ForeignKey, TIMESTAMP, LargeBinary, Identity
from sqlalchemy.orm import relationship

from src.database import Base


class ChatUser(Base):
    __tablename__ = "chatsusers"
    __table_args__ = {"extend_existing": True}
    id: int = Column(Integer, Identity(start=1), primary_key=True)
    chat_id: int = Column(Integer, ForeignKey("chats.id"), primary_key=True)
    user_id: int = Column(Integer, ForeignKey("users.id"), primary_key=True)
    public_key: str = Column(String, nullable=True)


class ChatType(Base):
    __tablename__ = "types"
    id: int = Column(Integer, primary_key=True)
    type: str = Column(String, nullable=False, unique=True)


class ChatPrime(Base):
    __tablename__ = "chatprime"
    id: int = Column(Integer, primary_key=True)
    chat_id: int = Column(Integer, ForeignKey("chats.id"), unique=True)
    p: str = Column(String)
    g: str = Column(String)
    chat = relationship("Chat", back_populates="primes")


class Chat(Base):
    __tablename__ = "chats"
    id: int = Column(Integer, primary_key=True)
    type_id: int = Column(Integer, ForeignKey("types.id"))
    name: str = Column(String, nullable=False)
    users = relationship("User", secondary="chatsusers", lazy="joined", back_populates="chats")
    primes = relationship("ChatPrime", lazy="joined", uselist=False, back_populates="chat")


class Message(Base):
    __tablename__ = "messages"
    id: int = Column(Integer, primary_key=True)
    timestamp: datetime = Column(TIMESTAMP, default=datetime.utcnow)
    body: bytes = Column(LargeBinary)
    chat_id: int = Column(Integer, ForeignKey("chats.id"))
    author = relationship("User", back_populates="messages")
    author_id = Column(Integer, ForeignKey("users.id"))

# class ChatUserKey(Base):
#     __tablename__ = "chatuserkey"
#     id: int = Column(Integer, primary_key=True)
#     user_id: int = Column(Integer, ForeignKey("users.id"), nullable=False)
#     chat_id: int = Column(Integer, ForeignKey("chats.id"), nullable=False)
