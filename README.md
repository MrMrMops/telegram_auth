# Telegram Auth API

Простой и безопасный сервис авторизации через Telegram с использованием JWT токенов, основанный на FastAPI. Этот проект включает интеграцию с Telegram Login Widget и работу с базой данных для хранения пользователей.

## 🚀 Возможности

- **Авторизация через Telegram Widget**: интеграция с Telegram для аутентификации.
- **Верификация подписи Telegram**: безопасность данных с использованием хэширования и подписи.
- **Генерация JWT токенов**: для безопасного обмена данными между клиентом и сервером.
- **Docker & Docker Compose**: для простого развертывания приложения в контейнерах.
- **Тестирование и безопасность**: пример использования переменных окружения и хэширования для безопасности.

## 📦 Стек технологий

- **FastAPI**: фреймворк для разработки REST API.
- **SQLAlchemy (async)**: асинхронный ORM для работы с базой данных.
- **SQLite/PostgreSQL**: использование SQLite для разработки, PostgreSQL для продакшн-среды.
- **Docker**: создание и деплой контейнеризованного приложения.
- **Telegram Login Widget**: интеграция с Telegram для аутентификации.
- **JWT (JSON Web Tokens)**: для безопасного обмена данными.
- **pytest**: для тестирования компонентов приложения.

## 🛠 Установка и запуск

### 🔧 Локальный запуск

1. **Клонируйте репозиторий**:
    ```bash
    git clone https://github.com/MrMrMops/telegram-auth-api.git
    cd telegram-auth-api
    ```

2. **Создайте файл `.env`** в корне проекта с параметрами:
    ```env
    TELEGRAM_BOT_TOKEN=ваш_токен_бота
    SECRET_KEY=ваш_jwt_секрет
    DATABASE_URL=sqlite+aiosqlite:///./app.db
    ```

3. **Установите зависимости**:
    ```bash
    pip install -r requirements.txt
    ```

4. **Запустите сервер**:
    ```bash
    uvicorn app.main:app --reload
    ```

### 🐳 Запуск с Docker

1. **Соберите образ**:
    ```bash
    docker build -t telegram-auth .
    ```

2. **Запустите контейнер**:
    ```bash
    docker run --env-file .env -p 8000:8000 telegram-auth
    ```

   Или используйте **Docker Compose** для удобства:
   ```bash
   docker-compose up --build
