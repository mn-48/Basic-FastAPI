from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional
from pydantic import BaseModel

# FastAPI অ্যাপ তৈরি
app = FastAPI()

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

# ফেক ডাটাবেস (উদাহরণের জন্য)
fake_users_db = {
    "testuser": {
        "username": "testuser",
        "email": "testuser@example.com",
        "hashed_password": pwd_context.hash("testpassword"),
        "disabled": False,
    }
}

# পাসওয়ার্ড ভেরিফাই
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# ইউজার পাওয়া
def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)
    return None

# ইউজার অথেনটিকেট
def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
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
async def get_current_user(token: str = Depends(oauth2_scheme)):
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
    user = get_user(fake_users_db, username=username)
    if user is None:
        raise credentials_exception
    return user

# টোকেন জেনারেট করার এন্ডপয়েন্ট
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
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

# সুরক্ষিত এন্ডপয়েন্ট
@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user