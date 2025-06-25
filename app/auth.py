from fastapi import HTTPException
from fastapi.responses import JSONResponse
from hashlib import sha256
import hmac
import time
import os
from sqlalchemy import select
from dotenv import load_dotenv
from datetime import datetime, timedelta
from jose import jwt

from app.models import User

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY")  # храни в .env
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 дней
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")


async def telegram_auth_func(request,db):
    data = dict(request.query_params)   

    # Проверка подписи Telegram
    if not verify_telegram_auth(data.copy()):
        raise HTTPException(status_code=403, detail="Invalid Telegram auth")

    # Проверка срока действия (можно: ±1 день)
    auth_date = int(data.get("auth_date", 0))
    if time.time() - auth_date > 86400:
        raise HTTPException(status_code=403, detail="Telegram auth expired")

    telegram_id = data["id"]
    username = data.get("username")

    # Поиск пользователя
    result = await db.execute(
        select(User).where(User.telegram_id == telegram_id)
    )
    user = result.scalar_one_or_none()

    if not user:
        # Если пользователя нет — создаём
        user = User(telegram_id=telegram_id, username=username)
        db.add(user)
        await db.commit()
        await db.refresh(user)

    # Генерация токена
    token = create_access_token({"sub": str(user.id)})

    return JSONResponse({"access_token": token})


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_telegram_auth(data: dict) -> bool:
    """Проверка валидности хэша (подписи) от Telegram."""
    received_hash = data.pop("hash")
    auth_data = sorted([f"{k}={v}" for k, v in data.items()])
    data_check_string = "\n".join(auth_data)
    secret_key = sha256(TELEGRAM_BOT_TOKEN.encode()).digest()
    hmac_hash = hmac.new(secret_key, msg=data_check_string.encode(), digestmod=sha256).hexdigest()
    return hmac_hash == received_hash
