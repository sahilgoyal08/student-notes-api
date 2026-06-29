from pydantic import BaseModel

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

