from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import APIRouter
from pydantic import BaseModel
from typing import List
from passlib.context import CryptContext
from jose import JWTError, jwt

app = FastAPI()
router = APIRouter()

SECRET_KEY = "your_secret_key"  # Замените на свой безопасный ключ
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class User(BaseModel):
    username: str
    password: str

class UserInDB(User):
    hashed_password: str

users_db = {}
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expire_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    to_encode = data.copy()
    to_encode.update({"exp": jwt.encode({'exp': expire_minutes}, key=SECRET_KEY, algorithm=ALGORITHM)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@router.post("/register", response_model=User)
async def register(user: User):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_password = get_password_hash(user.password)
    users_db[user.username] = UserInDB(**user.dict(), hashed_password=hashed_password)
    return user

@router.post("/token", response_model=dict)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/logout")
async def logout():
    return {"msg": "Logged out successfully"}

@router.get("/users/", response_model=List[User])
async def get_users():
    return list(users_db.values())

app.include_router(router, prefix="/auth")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
