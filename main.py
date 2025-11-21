import os
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import base64
import json
from bson import ObjectId

from database import db, create_document, get_documents

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Simple token auth (HMAC JWT-like)
# -----------------------------

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
TOKEN_EXP_MINUTES = 60 * 24

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(sub: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": sub,
        "exp": int((datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXP_MINUTES)).timestamp()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
    }
    h64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=")
    p64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
    sig = hmac.new(SECRET_KEY.encode(), h64 + b"." + p64, hashlib.sha256).digest()
    s64 = base64.urlsafe_b64encode(sig).rstrip(b"=")
    return (h64 + b"." + p64 + b"." + s64).decode()

def verify_token(token: str) -> Optional[str]:
    try:
        h64, p64, s64 = token.split(".")
        expected = base64.urlsafe_b64encode(
            hmac.new(SECRET_KEY.encode(), (h64 + "." + p64).encode(), hashlib.sha256).digest()
        ).rstrip(b"=")
        if expected.decode() != s64:
            return None
        payload = json.loads(base64.urlsafe_b64decode(p64 + "=="))
        if payload.get("exp", 0) < int(datetime.now(timezone.utc).timestamp()):
            return None
        return payload.get("sub")
    except Exception:
        return None

# -----------------------------
# Models
# -----------------------------

class RegisterIn(BaseModel):
    name: str = Field(..., min_length=2)
    email: EmailStr
    password: str = Field(..., min_length=6)

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class TokenOut(BaseModel):
    token: str

class ProductIn(BaseModel):
    name: str = Field(..., min_length=2)
    description: Optional[str] = None
    price: float = Field(..., ge=0)
    image: Optional[str] = None
    in_stock: bool = True

class ProductOut(ProductIn):
    id: str
    owner_id: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

# -----------------------------
# Helpers
# -----------------------------

async def get_current_user(authorization: Optional[str] = Header(default=None)) -> Optional[dict]:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    token = authorization.split(" ", 1)[1]
    sub = verify_token(token)
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db["user"].find_one({"_id": ObjectId(sub)})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    user["id"] = str(user["_id"])  # attach string id
    return user

# -----------------------------
# Public endpoints
# -----------------------------

@app.get("/")
def read_root():
    return {"message": "E-Commerce Admin API"}

@app.get("/shop", response_model=List[ProductOut])
def public_shop():
    items = get_documents("product")
    mapped = []
    for d in items:
        d["id"] = str(d.get("_id"))
        d.pop("_id", None)
        mapped.append(d)
    return mapped

# -----------------------------
# Auth endpoints
# -----------------------------

@app.post("/auth/register", response_model=TokenOut)
def register(data: RegisterIn):
    existing = db["user"].find_one({"email": data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "name": data.name,
        "email": data.email,
        "password_hash": hash_password(data.password),
        "role": "admin",
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["user"].insert_one(user_doc)
    token = create_token(str(res.inserted_id))
    return {"token": token}

@app.post("/auth/login", response_model=TokenOut)
def login(data: LoginIn):
    user = db["user"].find_one({"email": data.email})
    if not user or user.get("password_hash") != hash_password(data.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(str(user["_id"]))
    return {"token": token}

# -----------------------------
# Protected Product CRUD
# -----------------------------

@app.get("/admin/products", response_model=List[ProductOut])
async def list_products(user=Depends(get_current_user)):
    items = get_documents("product")
    mapped = []
    for d in items:
        d["id"] = str(d.get("_id"))
        d.pop("_id", None)
        mapped.append(d)
    return mapped

@app.post("/admin/products", response_model=ProductOut)
async def create_product(payload: ProductIn, user=Depends(get_current_user)):
    data = payload.model_dump()
    data["owner_id"] = str(user["_id"]) if user.get("_id") else None
    inserted_id = create_document("product", data)
    doc = db["product"].find_one({"_id": ObjectId(inserted_id)})
    doc_out = dict(doc)
    doc_out["id"] = str(doc_out.pop("_id"))
    return doc_out

@app.put("/admin/products/{product_id}", response_model=ProductOut)
async def update_product(product_id: str, payload: ProductIn, user=Depends(get_current_user)):
    try:
        oid = ObjectId(product_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid product id")

    update = payload.model_dump()
    update["updated_at"] = datetime.now(timezone.utc)
    res = db["product"].update_one({"_id": oid}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    doc = db["product"].find_one({"_id": oid})
    doc_out = dict(doc)
    doc_out["id"] = str(doc_out.pop("_id"))
    return doc_out

@app.delete("/admin/products/{product_id}")
async def delete_product(product_id: str, user=Depends(get_current_user)):
    try:
        oid = ObjectId(product_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid product id")
    res = db["product"].delete_one({"_id": oid})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"ok": True}

# -----------------------------
# Diagnostics
# -----------------------------

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
