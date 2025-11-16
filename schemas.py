"""
Database Schemas for Proton

Each Pydantic model represents a MongoDB collection with the collection name as the lowercase of the class name.
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import datetime

Role = Literal["vendor", "buyer", "investor", "employee", "admin"]
KYCStatus = Literal["pending", "approved", "rejected"]
OrderStatus = Literal["draft", "submitted", "in_progress", "completed", "cancelled"]
InvestmentStatus = Literal["initiated", "processing", "successful", "failed", "refunded"]
ApplicationStatus = Literal["applied", "review", "interview", "offer", "rejected", "hired"]

class User(BaseModel):
    name: str
    email: EmailStr
    phone: Optional[str] = None
    role: Role
    password_hash: str
    kyc_status: KYCStatus = "pending"
    company_id: Optional[str] = None
    is_active: bool = True

class Company(BaseModel):
    name: str
    description: Optional[str] = None
    address: Optional[str] = None
    certifications: List[str] = []
    categories: List[str] = []
    capacity_per_month: Optional[int] = None
    contact_email: Optional[EmailStr] = None
    contact_phone: Optional[str] = None

class Vendorprofile(BaseModel):
    # vendorprofile -> collection name "vendorprofile"
    user_id: str
    company_id: Optional[str] = None
    capabilities: List[str] = []
    compliance_docs: List[str] = []  # URLs to S3/Cloudinary
    approved: bool = False

class Productlisting(BaseModel):
    # productlisting -> collection name "productlisting"
    vendor_id: str
    title: str
    specs: Optional[str] = None
    category: Optional[str] = None
    unit_price: Optional[float] = None
    images: List[str] = []
    in_stock: bool = True

class Buyerrequirement(BaseModel):
    # buyerrequirement -> collection name "buyerrequirement"
    buyer_id: str
    title: str
    description: Optional[str] = None
    budget: Optional[float] = None
    deadline: Optional[str] = None
    status: OrderStatus = "submitted"

class Investmentproject(BaseModel):
    # investmentproject -> collection name "investmentproject"
    title: str
    description: Optional[str] = None
    target_amount: float
    expected_roi_pct: float
    duration_months: int
    owner_vendor_id: Optional[str] = None
    milestones: List[str] = []

class Transaction(BaseModel):
    investor_id: str
    project_id: str
    amount: float
    status: InvestmentStatus = "initiated"

class Joblisting(BaseModel):
    title: str
    company_id: Optional[str] = None
    location: Optional[str] = None
    skills: List[str] = []
    min_exp_years: Optional[int] = None
    description: Optional[str] = None

class Jobapplication(BaseModel):
    job_id: str
    user_id: str
    status: ApplicationStatus = "applied"
    resume_url: Optional[str] = None

class Kycrecord(BaseModel):
    user_id: str
    provider: Literal["digilocker"] = "digilocker"
    reference_id: Optional[str] = None
    status: KYCStatus = "pending"
