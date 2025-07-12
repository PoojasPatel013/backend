from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings
from typing import Optional

class Database:
    client: Optional[AsyncIOMotorClient] = None
    db = None

    @classmethod
    async def connect_db(cls):
        try:
            if cls.client is None:
                cls.client = AsyncIOMotorClient(settings.mongodb_url)
                cls.db = cls.client[settings.database_name]
                print(f"Connected to MongoDB at {settings.mongodb_url}")
                
                # Test connection
                await cls.db.command("ping")
                print("MongoDB connection successful")
        except Exception as e:
            print(f"Error connecting to MongoDB: {str(e)}")
            cls.client = None
            cls.db = None
            raise

    @classmethod
    async def close_db(cls):
        if cls.client:
            await cls.client.close()
            print("Closed MongoDB connection")
            cls.client = None
            cls.db = None

    @classmethod
    async def get_models_collection(cls):
        if cls.db is None:
            raise Exception("Database not initialized")
        return cls.db[settings.models_collection]
        
    @classmethod
    async def get_users_collection(cls):
        if cls.db is None:
            raise Exception("Database not initialized")
        return cls.db[settings.users_collection]
