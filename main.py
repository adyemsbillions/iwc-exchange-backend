from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import pymysql
from pymysql.err import IntegrityError  
from database import get_db_connection
from routes.dashboard import router as dashboard_router
app = FastAPI(title="IWC Exchange")

# Security config
SECRET_KEY = "iwc-exchange-super-secret-key-2025-change-this"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    confirm_password: str


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return email
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

def create_access_token(email: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": email, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)


@app.post("/signup")
async def signup(request: SignupRequest):
    if request.password != request.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    hashed_password = pwd_context.hash(request.password)

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (email, password_hash) VALUES (%s, %s)",
                (request.email, hashed_password)
            )
        conn.commit()
        return {"message": "Signup successful"}
    except pymysql.err.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already registered")
    except Exception:
        raise HTTPException(status_code=500, detail="Server error")
    finally:
        conn.close()


@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email = %s", (form_data.username,))
            user = cur.fetchone()
    finally:
        conn.close()

    if not user or not pwd_context.verify(form_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(user["email"])
    return {"access_token": access_token, "token_type": "bearer"}

# Include the protected dashboard route
app.include_router(dashboard_router)