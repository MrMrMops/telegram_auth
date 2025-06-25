from fastapi import APIRouter, FastAPI, Request, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from dotenv import load_dotenv

from app.auth import telegram_auth_func
from app.db import get_db, engine
from app.models import Base

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Или строго указать фронтенд-URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def on_startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

router = APIRouter(prefix="/auth", tags=["Auth"])

@router.get("/telegram")
async def telegram_auth(request: Request, db: AsyncSession = Depends(get_db)):
    return await telegram_auth_func(request,db)

app.include_router(router)