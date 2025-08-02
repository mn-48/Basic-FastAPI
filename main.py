from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional
from pydantic import BaseModel
import asyncpg
import uuid

# FastAPI অ্যাপ তৈরি
app = FastAPI()

# PostgreSQL কনফিগারেশন
DATABASE_URL = "postgresql://nazmul:123456@localhost:5432/authdb"

# সিক্রেট কী এবং অ্যালগরিদম
SECRET_KEY = "your-secret-key"  # প্রোডাকশনে এটি সিকিউর কী ব্যবহার করুন
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# পাসওয়ার্ড হ্যাশিং
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 স্কিম
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ইউজার মডেল
class User(BaseModel):
    username: str
    email: Optional[str] = None
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

# টোকেন মডেল
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

# টোকেন ভেরিফিকেশন মডেল
class TokenVerifyRequest(BaseModel):
    token: str
    token_type: str  # "access" বা "refresh"

class TokenVerifyResponse(BaseModel):
    valid: bool
    message: str
    username: Optional[str] = None

# ডাটাবেস কানেকশন পুল তৈরি
async def get_db():
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        await conn.close()

# ইউজার তৈরি করার ফাংশন
async def create_user(conn, username: str, email: str, password: str):
    hashed_password = pwd_context.hash(password)
    query = """
    INSERT INTO users (username, email, hashed_password, disabled)
    VALUES ($1, $2, $3, $4)
    RETURNING username, email, hashed_password, disabled
    """
    try:
        user = await conn.fetchrow(query, username, email, hashed_password, False)
        return UserInDB(**user)
    except asyncpg.UniqueViolationError:
        raise HTTPException(status_code=400, detail="Username already exists")

# পাসওয়ার্ড ভেরিফাই
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# ইউজার পাওয়া
async def get_user(conn, username: str):
    query = "SELECT username, email, hashed_password, disabled FROM users WHERE username = $1"
    user = await conn.fetchrow(query, username)
    if user:
        return UserInDB(**user)
    return None

# ইউজার অথেনটিকেট
async def authenticate_user(conn, username: str, password: str):
    user = await get_user(conn, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

# JWT অ্যাক্সেস টোকেন তৈরি
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# JWT রিফ্রেশ টোকেন তৈরি
def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# রিফ্রেশ টোকেন সংরক্ষণ
async def store_refresh_token(conn, user_id: str, refresh_token: str):
    token_id = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    query = """
    INSERT INTO refresh_tokens (token_id, user_id, refresh_token, expires_at)
    VALUES ($1, $2, $3, $4)
    """
    await conn.execute(query, token_id, user_id, refresh_token, expires_at)

# রিফ্রেশ টোকেন ভেরিফাই
async def verify_refresh_token(conn, refresh_token: str):
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        query = "SELECT user_id FROM refresh_tokens WHERE refresh_token = $1 AND expires_at > $2"
        result = await conn.fetchrow(query, refresh_token, datetime.utcnow())
        if result is None:
            return None
        return username
    except JWTError:
        return None

# টোকেন ভেরিফাই ফাংশন
async def verify_token(token: str, token_type: str, conn):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return TokenVerifyResponse(valid=False, message="Invalid token: No username in payload")
        
        if token_type == "access":
            user = await get_user(conn, username)
            if user is None or user.disabled:
                return TokenVerifyResponse(valid=False, message="Invalid token: User not found or disabled")
            return TokenVerifyResponse(valid=True, message="Access token is valid", username=username)
        
        elif token_type == "refresh":
            username_from_db = await verify_refresh_token(conn, token)
            if username_from_db is None:
                return TokenVerifyResponse(valid=False, message="Invalid or expired refresh token")
            return TokenVerifyResponse(valid=True, message="Refresh token is valid", username=username_from_db)
        
        else:
            return TokenVerifyResponse(valid=False, message="Invalid token type specified")
    except JWTError:
        return TokenVerifyResponse(valid=False, message="Invalid token: Failed to decode")

# রিফ্রেশ টোকেন রিভোক
async def revoke_refresh_token(conn, refresh_token: str, username: str):
    query = """
    DELETE FROM refresh_tokens 
    WHERE refresh_token = $1 AND user_id = $2
    """
    result = await conn.execute(query, refresh_token, username)
    if result == "DELETE 0":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Refresh token not found or already revoked"
        )

# বর্তমান ইউজার পাওয়া
async def get_current_user(token: str = Depends(oauth2_scheme), conn = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await get_user(conn, username=username)
    if user is None:
        raise credentials_exception
    return user

# ডাটাবেস টেবিল তৈরি
async def init_db():
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username VARCHAR(50) PRIMARY KEY,
                email VARCHAR(100) NOT NULL,
                hashed_password TEXT NOT NULL,
                disabled BOOLEAN NOT NULL
            )
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token_id VARCHAR(36) PRIMARY KEY,
                user_id VARCHAR(50) NOT NULL,
                refresh_token TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (username)
            )
        """)
    finally:
        await conn.close()

# অ্যাপ স্টার্টআপে ডাটাবেস ইনিশিয়ালাইজ
@app.on_event("startup")
async def startup_event():
    await init_db()

# টোকেন জেনারেট করার এন্ডপয়েন্ট
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), conn = Depends(get_db)):
    user = await authenticate_user(conn, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(
        data={"sub": user.username}, expires_delta=refresh_token_expires
    )
    await store_refresh_token(conn, user.username, refresh_token)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

# রিফ্রেশ টোকেন এন্ডপয়েন্ট
@app.post("/refresh", response_model=Token)
async def refresh_access_token(refresh_token: str, conn = Depends(get_db)):
    username = await verify_refresh_token(conn, refresh_token)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token = create_access_token(
        data={"sub": username}, expires_delta=access_token_expires
    )
    new_refresh_token = create_refresh_token(
        data={"sub": username}, expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )
    await store_refresh_token(conn, username, new_refresh_token)
    return {"access_token": new_access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}

# রিফ্রেশ টোকেন রিভোক এন্ডপয়েন্ট
@app.post("/revoke")
async def revoke_token(refresh_token: str, current_user: User = Depends(get_current_user), conn = Depends(get_db)):
    await revoke_refresh_token(conn, refresh_token, current_user.username)
    return {"message": "Refresh token revoked successfully"}

# টোকেন ভেরিফাই এন্ডপয়েন্ট
@app.post("/verify", response_model=TokenVerifyResponse)
async def verify_token_endpoint(request: TokenVerifyRequest, conn = Depends(get_db)):
    return await verify_token(request.token, request.token_type, conn)

# ইউজার তৈরির এন্ডপয়েন্ট
@app.post("/users/")
async def create_new_user(username: str, email: str, password: str, conn = Depends(get_db)):
    user = await create_user(conn, username, email, password)
    return user

# সুরক্ষিত এন্ডপয়েন্ট
@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user