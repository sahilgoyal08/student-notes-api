from security import get_password_hash, verify_password, create_access_token, SECRET_KEY, ALGORITHM
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import APIRouter, HTTPException, status, Depends
import jwt
from database.database import get_db_connection
from models.schemas import UserCreate, UserResponse, Token
from psycopg2.extras import RealDictCursor
from psycopg2.errors import UniqueViolation 

router = APIRouter(tags=["Authentication"])

@router.get("/")
def returning():
    try:
        conn = get_db_connection()
        conn.close()
        return {"status": "Success!", "message": "Securely connected to PostgreSQL using .env"}
    except Exception as e:
        return {"status": "Failed", "error": str(e)}
    

@router.post("/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
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
    except UniqueViolation:
        conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="That username is already taken."
        )
    finally:
        conn.close()

@router.post("/login", response_model=Token)
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
