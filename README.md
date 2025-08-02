# Install FastAPI
```
pip install "fastapi[standard]"
```


# RUN
```
fastapi dev main.py

uvicorn main:app --reload

```

# OAuth2
```
pip install fastapi uvicorn python-jose[cryptography] passlib[bcrypt] python-multipart

```


# db
```
DATABASE_URL = "postgresql://user:password@localhost:5432/authdb"

```