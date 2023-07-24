import uvicorn
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import create_engine
from app.router import router
from database.connection import Base, engine
from fastapi.middleware.cors import CORSMiddleware

db = create_engine('postgresql://postgres:123321@localhost:5432/cabinet')
app = FastAPI()
Base.metadata.create_all(bind=engine)
app.add_middleware(SessionMiddleware, secret_key="dajhsdkjhaskjd")
app.include_router(router)

origins = [
    "*",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if __name__ == "__main__":
    uvicorn.run("main:app", reload=True, port=5000)