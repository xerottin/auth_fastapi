from fastapi import FastAPI

from app import auth

app = FastAPI()

app.include_router(auth.router)

@app.post("/")
async def root():
    return {"Hello": "World"}


