import bcrypt
import os
import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load our secret key from the .env file
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

# --- EXISTING HASHING FUNCTIONS ---
def get_password_hash(password: str) -> str:
    pwd_bytes = password.encode('utf-8')
    hashed_bytes = bcrypt.hashpw(pwd_bytes, bcrypt.gensalt())
    return hashed_bytes.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    pwd_bytes = plain_password.encode('utf-8')
    hash_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(pwd_bytes, hash_bytes)

# --- NEW: JWT TOKEN GENERATOR ---
def create_access_token(data: dict):
    to_encode = data.copy()
    
    # Make the token expire in 1 hour for security
    expire = datetime.utcnow() + timedelta(hours=1)
    to_encode.update({"exp": expire})
    
    # Create the cryptographically signed badge
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt