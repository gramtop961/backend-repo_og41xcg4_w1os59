import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import jwt
from passlib.context import CryptContext

from database import db, create_document, get_documents

# App and CORS
app = FastAPI(title="Proton API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
JWT_SECRET = os.getenv("JWT_SECRET", "dev_secret_change_me")
JWT_ALG = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Utilities

def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)


def verify_password(pw: str, hashed: str) -> bool:
    return pwd_context.verify(pw, hashed)


def create_token(data: dict, expires_minutes: int = 60) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Schemas (request/response)
class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str  # vendor | buyer | investor | employee | admin


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]


class ProductPayload(BaseModel):
    title: str
    specs: Optional[str] = None
    category: Optional[str] = None
    unit_price: Optional[float] = None
    images: List[str] = []


class RequirementPayload(BaseModel):
    title: str
    description: Optional[str] = None
    budget: Optional[float] = None
    deadline: Optional[str] = None


class ProjectPayload(BaseModel):
    title: str
    description: Optional[str] = None
    target_amount: float
    expected_roi_pct: float
    duration_months: int
    milestones: List[str] = []


class InvestPayload(BaseModel):
    project_id: str
    amount: float


class JobPayload(BaseModel):
    title: str
    company_id: Optional[str] = None
    location: Optional[str] = None
    skills: List[str] = []
    min_exp_years: Optional[int] = None
    description: Optional[str] = None


class ApplyPayload(BaseModel):
    job_id: str
    resume_url: Optional[str] = None


# Auth dependency

def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Invalid auth header")
    payload = decode_token(token)
    user = db["user"].find_one({"email": payload.get("sub")})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    # sanitize
    user["_id"] = str(user["_id"]) if "_id" in user else None
    user.pop("password_hash", None)
    return user


# Health and info
@app.get("/")
def root():
    return {"message": "Proton API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "❌ Not Set",
        "database_name": "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": [],
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = os.getenv("DATABASE_NAME") or "❌ Not Set"
            collections = db.list_collection_names()
            response["collections"] = collections[:10]
            response["connection_status"] = "Connected"
            response["database"] = "✅ Connected & Working"
    except Exception as e:
        response["database"] = f"⚠️ Error: {str(e)}"
    return response


# Schemas endpoint to support viewers
@app.get("/schema")
def get_schema():
    # Minimal schema description for key collections
    return {
        "collections": [
            "user",
            "company",
            "vendorprofile",
            "productlisting",
            "buyerrequirement",
            "investmentproject",
            "transaction",
            "joblisting",
            "jobapplication",
            "kycrecord",
        ]
    }


# Authentication
@app.post("/auth/signup", response_model=AuthResponse)
def signup(payload: SignupRequest):
    email = payload.email.lower()
    existing = db["user"].find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "name": payload.name,
        "email": email,
        "phone": None,
        "role": payload.role,
        "password_hash": hash_password(payload.password),
        "kyc_status": "pending",
        "company_id": None,
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result = db["user"].insert_one(user_doc)
    sub = email
    token = create_token({"sub": sub, "role": payload.role})
    user_doc["_id"] = str(result.inserted_id)
    user_doc.pop("password_hash", None)
    return {"access_token": token, "user": user_doc}


@app.post("/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest):
    email = payload.email.lower()
    user = db["user"].find_one({"email": email})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="User deactivated")
    token = create_token({"sub": email, "role": user.get("role")})
    user["_id"] = str(user["_id"]) if "_id" in user else None
    user.pop("password_hash", None)
    return {"access_token": token, "user": user}


@app.get("/auth/me")
def me(user: dict = Depends(get_current_user)):
    return user


# Vendor endpoints
@app.post("/vendor/products")
def create_product(payload: ProductPayload, user: dict = Depends(get_current_user)):
    if user.get("role") != "vendor":
        raise HTTPException(status_code=403, detail="Only vendors can create products")
    doc = payload.dict()
    doc.update({"vendor_id": user.get("_id")})
    inserted_id = create_document("productlisting", doc)
    return {"id": inserted_id, "message": "Product listed"}


@app.get("/vendor/products")
def my_products(user: dict = Depends(get_current_user)):
    if user.get("role") != "vendor":
        raise HTTPException(status_code=403, detail="Only vendors can view this")
    docs = get_documents("productlisting", {"vendor_id": user.get("_id")})
    for d in docs:
        d["_id"] = str(d["_id"]) if "_id" in d else None
    return docs


# Buyer endpoints
@app.post("/buyer/requirements")
def create_requirement(payload: RequirementPayload, user: dict = Depends(get_current_user)):
    if user.get("role") != "buyer":
        raise HTTPException(status_code=403, detail="Only buyers can post requirements")
    doc = payload.dict()
    doc.update({"buyer_id": user.get("_id"), "status": "submitted"})
    inserted_id = create_document("buyerrequirement", doc)
    return {"id": inserted_id, "message": "Requirement posted"}


@app.get("/buyer/requirements")
def my_requirements(user: dict = Depends(get_current_user)):
    if user.get("role") != "buyer":
        raise HTTPException(status_code=403, detail="Only buyers can view this")
    docs = get_documents("buyerrequirement", {"buyer_id": user.get("_id")})
    for d in docs:
        d["_id"] = str(d["_id"]) if "_id" in d else None
    return docs


# Investor endpoints
@app.post("/investor/projects")
def create_project(payload: ProjectPayload, user: dict = Depends(get_current_user)):
    if user.get("role") not in ("vendor", "admin"):
        raise HTTPException(status_code=403, detail="Only vendors or admins can create projects")
    doc = payload.dict()
    doc.update({"owner_vendor_id": user.get("_id")})
    inserted_id = create_document("investmentproject", doc)
    return {"id": inserted_id, "message": "Project created"}


@app.get("/investor/projects")
def list_projects():
    docs = get_documents("investmentproject")
    for d in docs:
        d["_id"] = str(d["_id"]) if "_id" in d else None
    return docs


@app.post("/investor/invest")
def invest(payload: InvestPayload, user: dict = Depends(get_current_user)):
    if user.get("role") != "investor":
        raise HTTPException(status_code=403, detail="Only investors can invest")
    doc = {
        "investor_id": user.get("_id"),
        "project_id": payload.project_id,
        "amount": payload.amount,
        "status": "initiated",
    }
    inserted_id = create_document("transaction", doc)
    return {"id": inserted_id, "message": "Investment initiated"}


# Jobs endpoints
@app.post("/job/listings")
def create_job(payload: JobPayload, user: dict = Depends(get_current_user)):
    if user.get("role") not in ("vendor", "admin"):
        raise HTTPException(status_code=403, detail="Only vendors/admins can post jobs")
    doc = payload.dict()
    inserted_id = create_document("joblisting", doc)
    return {"id": inserted_id, "message": "Job posted"}


@app.get("/job/listings")
def list_jobs():
    docs = get_documents("joblisting")
    for d in docs:
        d["_id"] = str(d["_id"]) if "_id" in d else None
    return docs


@app.post("/job/apply")
def apply_job(payload: ApplyPayload, user: dict = Depends(get_current_user)):
    if user.get("role") not in ("employee", "admin"):
        raise HTTPException(status_code=403, detail="Only employees/admins can apply")
    doc = {"job_id": payload.job_id, "user_id": user.get("_id"), "status": "applied", "resume_url": payload.resume_url}
    inserted_id = create_document("jobapplication", doc)
    return {"id": inserted_id, "message": "Application submitted"}


# Admin
@app.get("/admin/overview")
def admin_overview(user: dict = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    def count(col):
        try:
            return db[col].count_documents({})
        except Exception:
            return 0
    return {
        "users": count("user"),
        "products": count("productlisting"),
        "requirements": count("buyerrequirement"),
        "projects": count("investmentproject"),
        "transactions": count("transaction"),
        "jobs": count("joblisting"),
        "applications": count("jobapplication"),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
