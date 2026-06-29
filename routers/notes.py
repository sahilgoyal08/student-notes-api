from security import get_password_hash, verify_password, create_access_token, SECRET_KEY, ALGORITHM
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import APIRouter, HTTPException, status, Depends
import jwt
from database.database import get_db_connection
from models.schemas import NoteCreate, NoteResponse
from psycopg2.extras import RealDictCursor

router = APIRouter(tags=['Notes'], prefix="/notes")
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



@router.post("/notes", response_model=NoteResponse)
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
@router.get("/notes")
def get_my_notes(current_user: str = Depends(get_current_user)):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    # The WHERE clause ensures they only see their own stuff
    cursor.execute("SELECT * FROM notes WHERE owner_username = %s", (current_user,))
    notes = cursor.fetchall()
    
    conn.close()
    return notes