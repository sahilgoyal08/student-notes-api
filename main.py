import psycopg2
from pydantic import BaseModel
from psycopg2.extras import RealDictCursor
import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, status, Depends
import jwt
from security import get_password_hash, verify_password, create_access_token, SECRET_KEY, ALGORITHM
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

app = FastAPI()

class NoteCreate(BaseModel):
    heading: str
    content: str

class NoteResponse(BaseModel):
    id: int
    heading: str
    content: str
    owner_username: str

# This tells FastAPI what our token response should look like
class Token(BaseModel):
    access_token: str
    token_type: str

class UserCreate(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    username: str
    id: int

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def setup_database():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Create users table (Already exists, Postgres will ignore it)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
    """)
    
    # 2. ADD THIS: Create notes table linked to the user
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notes (
        id SERIAL PRIMARY KEY,
        heading TEXT NOT NULL,
        content TEXT NOT NULL,
        owner_username TEXT NOT NULL REFERENCES users(username)
    )
    """)
    
    conn.commit()
    conn.close()
setup_database()

# This tells FastAPI where our users get their tokens
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# This is our bouncer function
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Try to decode the badge using our secret key
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        
        if username is None:
            raise credentials_exception
            
        # If it worked, hand the username to the route!
        return username
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise credentials_exception


@app.get("/")
def returning():
    try:
        conn = get_db_connection()
        conn.close()
        return {"status": "Success!", "message": "Securely connected to PostgreSQL using .env"}
    except Exception as e:
        return {"status": "Failed", "error": str(e)}
    

@app.post("/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(user: UserCreate):
    hashed_pwd= get_password_hash(user.password)
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id, username",
            (user.username, hashed_pwd)
        )
        new_user=cursor.fetchone()
        conn.commit()
        return new_user
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="That username is already taken."
        )
    finally:
        conn.close()

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    # Notice we now use form_data.username instead of user_credentials
    cursor.execute("SELECT * FROM users WHERE username = %s", (form_data.username,))
    user = cursor.fetchone()
    conn.close()
    
    # Notice we now use form_data.password
    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/protected-data")
def read_secret_data(current_user: str = Depends(get_current_user)):
    # If the code makes it inside this function, the token is 100% valid!
    return {
        "message": "You made it past the bouncer!", 
        "user": current_user,
        "secret": "Batman's real name is Bruce Wayne"
    }

# Create a note (Automatically assigns it to the logged-in user)
@app.post("/notes", response_model=NoteResponse)
def create_note(note: NoteCreate, current_user: str = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    cursor.execute(
        "INSERT INTO notes (heading, content, owner_username) VALUES (%s, %s, %s) RETURNING *",
        (note.heading, note.content, current_user) # We inject the bouncer's username here!
    )
    
    new_note = cursor.fetchone()
    conn.commit()
    conn.close()
    
    return new_note

# Get notes (Only fetches notes that belong to the logged-in user)
@app.get("/notes")
def get_my_notes(current_user: str = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    # The WHERE clause ensures they only see their own stuff
    cursor.execute("SELECT * FROM notes WHERE owner_username = %s", (current_user,))
    notes = cursor.fetchall()
    
    conn.close()
    return notes