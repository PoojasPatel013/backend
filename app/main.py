from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from contextlib import asynccontextmanager
import os
import subprocess
from datetime import datetime, timedelta, timezone
import shutil
from typing import Optional
from app.core.database import Database  
from app.core.config import settings    
from bson import ObjectId
from jose import JWTError, jwt
from passlib.context import CryptContext
from app.models.user import (  
    UserInDB, UserBase, UserCreate, UserResponse, 
    PyObjectId
)
from pydantic import BaseModel


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Starting up...")
    try:
        await Database.connect_db()
        
        # Create indexes
        users_collection = await Database.get_users_collection()
        await users_collection.create_index("username", unique=True)
        await users_collection.create_index("email", unique=True)
        
        yield
        
    except Exception as e:
        print(f"Startup error: {str(e)}")
        raise
    
    finally:
        print("Shutting down...")
        await Database.close_db()

# Create app instance
app = FastAPI(title="Puf", lifespan=lifespan)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins.split(','),  # Allow from frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT Settings
ALGORITHM = settings.algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes
SECRET_KEY = settings.secret_key
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic models
class Token(BaseModel):
    access_token: str
    token_type: str
    user: dict

class UserCreate(UserBase):
    password: str

# Base directory for model storage
MODEL_DIR = "models"
if not os.path.exists(MODEL_DIR):
    os.makedirs(MODEL_DIR)



def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt

async def authenticate_user(username: str, password: str):
    users_collection = await Database.get_users_collection()
    user_data = await users_collection.find_one({"username": username})
    
    if not user_data:
        return False
    
    user = UserInDB(**user_data)
    if not user.verify_password(password):
        return False
    
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    users_collection = await Database.get_users_collection()
    user_data = await users_collection.find_one({"username": username})
    if user_data is None:
        raise credentials_exception
    
    return UserInDB(**user_data)

# Register endpoint
@app.post("/register", response_model=UserResponse)
async def register_user(user: UserCreate):
    try:
        users_collection = await Database.get_users_collection()
        
        # Check if user already exists
        existing_user = await users_collection.find_one({"username": user.username})
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already registered"
            )

        existing_email = await users_collection.find_one({"email": user.email})
        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

        # Hash password
        hashed_password = pwd_context.hash(user.password)
        
        # Create user
        user_data = user.dict()
        user_data["hashed_password"] = hashed_password
        user_data["created_at"] = datetime.now(timezone.utc)
        
        result = await users_collection.insert_one(user_data)
        user_data["id"] = str(result.inserted_id)
        
        return UserResponse(**user_data)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        user = await authenticate_user(form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        access_token = create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        
        # Convert user to dictionary manually
        user_dict = {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "name": user.name,
            "avatar_url": user.avatar_url,
            "created_at": user.created_at.isoformat()
        }
        
        return {
            "access_token": access_token, 
            "token_type": "bearer",
            "user": user_dict
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.get("/me")
async def read_users_me(current_user: UserInDB = Depends(get_current_user)):
    return current_user.to_dict()

@app.post("/models/upload")
async def upload_model(
    model_file: UploadFile = File(...),
    version: Optional[str] = None,
    description: Optional[str] = None
):
    """Upload a new model version"""
    try:
        # Create version directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        version = version or timestamp
        version_dir = os.path.join(MODEL_DIR, version)
        os.makedirs(version_dir, exist_ok=True)

        # Save model file
        file_path = os.path.join(version_dir, model_file.filename)
        with open(file_path, "wb") as f:
            shutil.copyfileobj(model_file.file, f)

        # Add to DVC
        subprocess.run(["dvc", "add", file_path], check=True)
        subprocess.run(["dvc", "commit"], check=True)

        # Save to MongoDB
        models_collection = await Database.get_models_collection()
        model_data = {
            "version": version,
            "filename": model_file.filename,
            "description": description,
            "file_path": file_path,
            "created_at": datetime.now(),
            "dvc_path": f"{version}/{model_file.filename}"
        }
        await models_collection.insert_one(model_data)

        return JSONResponse({
            "message": "Model uploaded successfully",
            "version": version,
            "filename": model_file.filename
        })

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/models/versions")
async def list_versions():
    """List all available model versions"""
    try:
        models_collection = await Database.get_models_collection()
        cursor = models_collection.find().sort("created_at", -1)
        versions = []
        async for model in cursor:
            model["_id"] = str(model["_id"])
            model["created_at"] = model["created_at"].isoformat()
            versions.append(model)
        return versions
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/models/{version}")
async def get_model_info(version: str):
    """Get information about a specific model version"""
    try:
        models_collection = await Database.get_models_collection()
        model = await models_collection.find_one({"version": version})
        
        if not model:
            raise HTTPException(status_code=404, detail="Version not found")
        
        model["_id"] = str(model["_id"])
        model["created_at"] = model["created_at"].isoformat()
        return model
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
