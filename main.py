from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional
from pydantic import BaseModel
import asyncpg
from typing import Optional

# FastAPI অ্যাপ তৈরি
app = FastAPI()

# PostgreSQL কনফিগারেশন
# DATABASE_URL = "postgresql://user:password@localhost:5432/authdb"
DATABASE_URL = "postgresql://nazmul:123456@localhost:5432/authdb"

# সিক্রেট কী এবং অ্যালগরিদম
SECRET_KEY = "your-secret-key"  # প্রোডাকশনে এটি সিকিউর কী ব্যবহার করুন
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

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

# JWT টোকেন তৈরি
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

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
    finally:
        await conn.close()

# অ্যাপ স্টার্টআপে ডাটাবেস ইনিশিয়ালাইজ
@app.on_event("startup")
async def startup_event():
    await init_db()

# টোকেন জেনারেট করার এন্ডপয়েন্ট
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), conn = Depends(get_db)):
    user = await authenticate_user(conn, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# ইউজার তৈরির এন্ডপয়েন্ট
@app.post("/users/")
async def create_new_user(username: str, email: str, password: str, conn = Depends(get_db)):
    user = await create_user(conn, username, email, password)
    return user

# সুরক্ষিত এন্ডপয়েন্ট
@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user