from fastapi import FastAPI
from routers import auth, notes
from database.database import setup_database

app = FastAPI()
setup_database()
app.include_router(auth.router)
app.include_router(notes.router)

@app.get("/")
def root():
    return {"message": "API is online"}
