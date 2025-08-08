from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Dict
from datetime import datetime, timedelta
from passlib.context import CryptContext
import jwt
import uuid

# App setup
app = FastAPI()

# JWT config
SECRET_KEY = 'claSsework8000'
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Security utils
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# In-memory databases
users_db: Dict[str, dict] = {}  # key = username
accounts: Dict[str, float] = {}  # key = user_id

# Models
class UserRegister(BaseModel):
    username: str
    password: str

class Transaction(BaseModel):
    amount: float

# Utils
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None or username not in users_db:
            raise HTTPException(status_code=401, detail="Invalid token or user")
        return users_db[username]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
# 1. Signup
@app.post("/signup")
def signup(user: UserRegister):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    user_id = str(uuid.uuid4())
    users_db[user.username] = {
        "username": user.username,
        "hashed_password": get_password_hash(user.password),
        "id": user_id
    }
    accounts[user_id] = 0.0
    return {"message": "User created", "user_id": user_id}

# 2. Login (get token)
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_token({"sub": user["username"]}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": token, "token_type": "bearer"}

# 3. Deposit
@app.post("/deposit")
def deposit(txn: Transaction, current_user: dict = Depends(get_current_user)):
    if txn.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")
    accounts[current_user["id"]] += txn.amount
    return {"message": "Deposited", "balance": accounts[current_user["id"]]}

# 4. Withdraw
@app.post("/withdraw")
def withdraw(txn: Transaction, current_user: dict = Depends(get_current_user)):
    if txn.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")
    if txn.amount > accounts[current_user["id"]]:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    accounts[current_user["id"]] -= txn.amount
    return {"message": "Withdrawn", "balance": accounts[current_user["id"]]}

# 5. Balance
@app.get("/balance")
def get_balance(current_user: dict = Depends(get_current_user)):
    return {"user_id": current_user["id"], "balance": accounts[current_user["id"]]}