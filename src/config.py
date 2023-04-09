from pathlib import Path
from dotenv import load_dotenv
import os

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
PUBLIC_KEY = BASE_DIR / "keys" / "public.pem"
PRIVATE_KEY = BASE_DIR / "keys" / "private.pem"

DB_HOST = os.environ.get("DB_HOST")
DB_PORT = os.environ.get("DB_PORT")
DB_NAME = os.environ.get("DB_NAME")
DB_USER = os.environ.get("DB_USER")
DB_PASS = os.environ.get("DB_PASS")

DEFAULT_CHUNK_SIZE = 1024 * 1024 * 5
