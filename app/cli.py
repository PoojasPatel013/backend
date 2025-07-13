# backend/app/cli.py
from fastapi import APIRouter, HTTPException, Depends
from typing import Optional
import subprocess
import os
import json
from app.core.config import settings
from app.core.database import Database
from app.models.user import UserInDB

router = APIRouter()

@router.post("/api/cli/execute")
async def execute_cli(
    command: str,
    cwd: Optional[str] = None,
    current_user: UserInDB = Depends(get_current_user)
):
    """
    Execute a Puf command with proper security checks
    """
    try:
        # Validate command to prevent command injection
        if not command.startswith("puf"):
            raise HTTPException(status_code=400, detail="Invalid command")
            
        # Get model directory for the user
        if not cwd:
            cwd = os.path.join("models", current_user.username)
            os.makedirs(cwd, exist_ok=True)
            
        # Execute the command with PAGER=cat for better output handling
        result = subprocess.run(
            command.split(),
            cwd=cwd,
            capture_output=True,
            text=True,
            env={**os.environ, "PAGER": "cat"}
        )
        
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))