from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.database import get_db
from app import models
from sqlalchemy.orm import Session

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="login"
)
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES =30

def hash_password(password :str):
    return pwd_context.hash(password)
def verify_password(
    plain_password, 
    hashed_password
):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data : dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) +timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(
        to_encode, 
        SECRET_KEY, 
        algorithm=ALGORITHM
    )
    return encoded_jwt

def verify_access_token(token: str) -> int:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        user_id = payload.get("user_id")
        if user_id is None:
            raise HTTPException(
                status_code =status.HTTP_401_UNAUTHORIZED,
                detail = "Could not validate credentials"
            )
        return user_id
    except JWTError:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail= "Could not validate credentials"
        )
                        
def get_current_user(
    token : str= Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    user_id= verify_access_token(token)
    user=(
        db.query(models.User)
        .filter(models.User.id == user_id)
        .first()
    )
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )
    return user