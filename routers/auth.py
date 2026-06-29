from security import get_password_hash, verify_password, create_access_token, SECRET_KEY, ALGORITHM
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import APIRouter, HTTPException, status, Depends
import jwt
from database.database import get_db_connection
from models.schemas import UserCreate, UserResponse, Token
from psycopg2.extras import RealDictCursor
from psycopg2.errors import UniqueViolation 

router = APIRouter(tags=["Authentication"])
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

@router.get("/protected-data")
def read_secret_data(current_user: str = Depends(get_current_user)):
    # If the code makes it inside this function, the token is 100% valid!
    return {
        "message": "You made it past the bouncer!", 
        "user": current_user,
        "secret": "Batman's real name is Bruce Wayne"
    }
