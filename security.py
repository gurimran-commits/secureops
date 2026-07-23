from fastapi import Header, HTTPException
from typing import Optional

from secureops.config import API_KEY

def verify_api_key(
    x_api_key: Optional[str] = Header(default=None),
):
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
        )
