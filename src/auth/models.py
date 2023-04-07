from sqlalchemy import Column, Integer, String, Boolean

from src.database import Base


class User(Base):
    __tablename__ = "users"
    id: int = Column(Integer, primary_key=True)
    # username?
    hashed_password: str = Column(String(length=1024), nullable=False)
    uid: int = Column(Integer, primary_key=True)
    is_active: bool = Column(Boolean, default=True, nullable=False)
