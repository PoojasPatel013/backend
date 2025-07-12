import os
from pydantic import BaseSettings

class Settings(BaseSettings):
    mongodb_url: str = os.getenv("MONGODB_URL", "mongodb+srv://poojaspatel1375:HrG5GuCITWknXzVR@cluster0.h3pwxv6.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
    database_name: str = os.getenv("DATABASE_NAME", "puf_db")
    models_collection: str = os.getenv("MODELS_COLLECTION", "models")
    users_collection: str = os.getenv("USERS_COLLECTION", "users")
    
    # JWT Configuration
    secret_key: str = os.getenv("SECRET_KEY", "your-secret-key-here")
    algorithm: str = os.getenv("ALGORITHM", "HS256")
    access_token_expire_minutes: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    
    # CORS Configuration
    allowed_origins: str = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")

    def __init__(self):
        super().__init__()

settings = Settings()
