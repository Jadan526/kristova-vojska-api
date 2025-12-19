from datetime import datetime, timedelta, date
from typing import Optional, List, Dict

import os
import uuid
import jwt
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    Date,
    ForeignKey,
    Text,
)
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import (
    declarative_base,
    sessionmaker,
    Session,
    relationship,
)
from passlib.context import CryptContext

JWT_SECRET = "tvoj-super-tajni-kljuc-zamijeni-ovo"
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

PROFILE_MEDIA_DIR = "media/profile_images"
os.makedirs(PROFILE_MEDIA_DIR, exist_ok=True)

DATABASE_URL = "sqlite:///./community.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(user_id: int, role: str) -> str:
    payload = {
        "user_id": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="member")
    is_active = Column(Boolean, default=True)

    member_profile = relationship("MemberProfile", back_populates="user", uselist=False)


class MemberProfile(Base):
    __tablename__ = "member_profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, unique=True)

    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    date_of_birth = Column(Date, nullable=True)
    baptism_date = Column(Date, nullable=True)
    phone = Column(String, nullable=True)
    address = Column(String, nullable=True)
    talents = Column(JSON, nullable=True)
    profile_image_url = Column(String, nullable=True)

    formation_level = Column(String, nullable=True)
    service = Column(String, nullable=True)

    user = relationship("User", back_populates="member_profile")


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=True)
    location = Column(String, nullable=True)
    type = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class FormationMaterial(Base):
    __tablename__ = "formation_materials"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    url = Column(String, nullable=False)
    formation_level = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Poll(Base):
    __tablename__ = "polls"

    id = Column(Integer, primary_key=True, index=True)
    question = Column(Text, nullable=False)
    is_multi_choice = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    options = relationship("PollOption", back_populates="poll", cascade="all, delete")


class PollOption(Base):
    __tablename__ = "poll_options"

    id = Column(Integer, primary_key=True, index=True)
    poll_id = Column(Integer, ForeignKey("polls.id"), nullable=False)
    text = Column(String, nullable=False)

    poll = relationship("Poll", back_populates="options")
    votes = relationship("PollVote", back_populates="option", cascade="all, delete")


class PollVote(Base):
    __tablename__ = "poll_votes"

    id = Column(Integer, primary_key=True, index=True)
    poll_id = Column(Integer, ForeignKey("polls.id"), nullable=False)
    option_id = Column(Integer, ForeignKey("poll_options.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    option = relationship("PollOption", back_populates="votes")


class InstagramPost(Base):
    __tablename__ = "instagram_posts"

    id = Column(Integer, primary_key=True, index=True)
    ig_id = Column(String, unique=True, index=True)
    caption = Column(Text, nullable=True)
    media_url = Column(String, nullable=False)
    permalink = Column(String, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class UserBase(BaseModel):
    email: EmailStr
    full_name: str


class UserCreate(UserBase):
    password: str


class UserRead(UserBase):
    id: int
    role: str
    is_active: bool

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserRead


class MemberProfileBase(BaseModel):
    formation_level: Optional[str] = None
    service: Optional[str] = None
    talents: Optional[Dict[str, List[str]]] = None


class MemberProfileCreate(MemberProfileBase):
    user_id: int


class MemberProfileRead(MemberProfileBase):
    id: int
    user: UserRead
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    date_of_birth: Optional[date] = None
    baptism_date: Optional[date] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    profile_image_url: Optional[str] = None

    class Config:
        from_attributes = True


class CurrentProfileBase(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    date_of_birth: Optional[date] = None
    baptism_date: Optional[date] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    talents: Optional[Dict[str, List[str]]] = None


class CurrentProfileRead(CurrentProfileBase):
    id: int
    profile_image_url: Optional[str] = None

    class Config:
        from_attributes = True


class CurrentProfileUpdate(CurrentProfileBase):
    pass


class EventBase(BaseModel):
    title: str
    description: Optional[str] = None
    start_time: datetime
    end_time: Optional[datetime] = None
    location: Optional[str] = None
    type: Optional[str] = None


class EventCreate(EventBase):
    pass


class EventRead(EventBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


class FormationMaterialBase(BaseModel):
    title: str
    description: Optional[str] = None
    url: str
    formation_level: Optional[str] = None


class FormationMaterialCreate(FormationMaterialBase):
    pass


class FormationMaterialRead(FormationMaterialBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


class PollOptionRead(BaseModel):
    id: int
    text: str

    class Config:
        from_attributes = True


class PollBase(BaseModel):
    question: str
    is_multi_choice: bool = False


class PollCreate(PollBase):
    options: List[str]


class PollRead(PollBase):
    id: int
    is_active: bool
    created_at: datetime
    options: List[PollOptionRead]

    class Config:
        from_attributes = True


class PollVoteCreate(BaseModel):
    poll_id: int
    option_id: int


class InstagramPostRead(BaseModel):
    id: int
    caption: Optional[str] = None
    media_url: str
    permalink: str
    timestamp: datetime

    class Config:
        from_attributes = True


# NOVO: info o današnjem danu
class TodayInfo(BaseModel):
    today: date
    birthday: Optional[str] = None
    baptism: Optional[str] = None
    events: List[EventRead]


security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    token = credentials.credentials
    payload = decode_token(token)

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    user_id = payload.get("user_id")
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return user


def require_role(*allowed_roles: str):
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {', '.join(allowed_roles)}",
            )
        return current_user

    return role_checker


Base.metadata.create_all(bind=engine)

app = FastAPI(title="Community API", version="0.6.2")
app.mount("/media", StaticFiles(directory="media"), name="media")


@app.post("/auth/register", response_model=TokenResponse, tags=["auth"])
def register_user(user_in: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user_in.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    hashed_pwd = hash_password(user_in.password)
    user = User(
        email=user_in.email,
        full_name=user_in.full_name,
        hashed_password=hashed_pwd,
        role="member",
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    profile = MemberProfile(user_id=user.id)
    db.add(profile)
    db.commit()

    token = create_access_token(user.id, user.role)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=user,
    )


@app.post("/auth/login", response_model=TokenResponse, tags=["auth"])
def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == login_data.email).first()

    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    token = create_access_token(user.id, user.role)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=user,
    )


@app.get("/auth/me", response_model=UserRead, tags=["auth"])
def get_me(current_user: User = Depends(get_current_user)):
    return current_user


def _create_or_update_special_events(
    db: Session,
    user: User,
    profile: MemberProfile,
):
    today = date.today()
    start_year = today.year
    end_year = today.year + 10

    if profile.date_of_birth:
        for year in range(start_year, end_year + 1):
            dob_this_year = datetime(
                year=year,
                month=profile.date_of_birth.month,
                day=profile.date_of_birth.day,
                hour=9,
                minute=0,
            )
            birthday_title = (
                f"Sretan rođendan {profile.first_name or user.full_name} "
                f"{profile.last_name or ''}"
            ).strip()

            existing_birthday = (
                db.query(Event)
                .filter(
                    Event.type == "birthday",
                    Event.start_time == dob_this_year,
                    Event.title == birthday_title,
                )
                .first()
            )
            if not existing_birthday:
                db.add(
                    Event(
                        title=birthday_title,
                        description=None,
                        start_time=dob_this_year,
                        end_time=None,
                        location=None,
                        type="birthday",
                    )
                )

    if profile.baptism_date:
        for year in range(start_year, end_year + 1):
            bap_this_year = datetime(
                year=year,
                month=profile.baptism_date.month,
                day=profile.baptism_date.day,
                hour=9,
                minute=0,
            )
            baptism_title = (
                f"Sretan krštenjedan {profile.first_name or user.full_name} "
                f"{profile.last_name or ''}"
            ).strip()

            existing_baptism = (
                db.query(Event)
                .filter(
                    Event.type == "baptism",
                    Event.start_time == bap_this_year,
                    Event.title == baptism_title,
                )
                .first()
            )
            if not existing_baptism:
                db.add(
                    Event(
                        title=baptism_title,
                        description=None,
                        start_time=bap_this_year,
                        end_time=None,
                        location=None,
                        type="baptism",
                    )
                )


@app.get("/me/profile", response_model=CurrentProfileRead, tags=["profile"])
def get_my_profile(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    profile = (
        db.query(MemberProfile)
        .filter(MemberProfile.user_id == current_user.id)
        .first()
    )
    if not profile:
        profile = MemberProfile(user_id=current_user.id)
        db.add(profile)
        db.commit()
        db.refresh(profile)
    return profile


@app.put("/me/profile", response_model=CurrentProfileRead, tags=["profile"])
def update_my_profile(
    profile_in: CurrentProfileUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    profile = (
        db.query(MemberProfile)
        .filter(MemberProfile.user_id == current_user.id)
        .first()
    )
    if not profile:
        profile = MemberProfile(user_id=current_user.id)
        db.add(profile)
        db.commit()
        db.refresh(profile)

    profile.first_name = profile_in.first_name
    profile.last_name = profile_in.last_name
    profile.date_of_birth = profile_in.date_of_birth
    profile.baptism_date = profile_in.baptism_date
    profile.phone = profile_in.phone
    profile.address = profile_in.address
    profile.talents = profile_in.talents

    _create_or_update_special_events(db, current_user, profile)

    db.commit()
    db.refresh(profile)
    return profile


@app.post("/me/profile-image", response_model=CurrentProfileRead, tags=["profile"])
def upload_profile_image(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    profile = (
        db.query(MemberProfile)
        .filter(MemberProfile.user_id == current_user.id)
        .first()
    )
    if not profile:
        profile = MemberProfile(user_id=current_user.id)
        db.add(profile)
        db.commit()
        db.refresh(profile)

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in [".jpg", ".jpeg", ".png", ".gif"]:
        raise HTTPException(status_code=400, detail="Unsupported image type")

    filename = f"{current_user.id}_{uuid.uuid4().hex}{ext}"
    filepath = os.path.join(PROFILE_MEDIA_DIR, filename)

    with open(filepath, "wb") as buffer:
        buffer.write(file.file.read())

    profile.profile_image_url = f"/media/profile_images/{filename}"
    db.commit()
    db.refresh(profile)
    return profile


@app.get("/me/today", response_model=TodayInfo, tags=["profile"])
def get_today_info(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    today = date.today()

    profile = (
        db.query(MemberProfile)
        .filter(MemberProfile.user_id == current_user.id)
        .first()
    )

    birthday_msg: Optional[str] = None
    baptism_msg: Optional[str] = None

    if profile and profile.date_of_birth:
        if (
            profile.date_of_birth.month == today.month
            and profile.date_of_birth.day == today.day
        ):
            birthday_msg = (
                f"Sretan rođendan {profile.first_name or current_user.full_name} "
                f"{profile.last_name or ''}"
            ).strip()

    if profile and profile.baptism_date:
        if (
            profile.baptism_date.month == today.month
            and profile.baptism_date.day == today.day
        ):
            baptism_msg = (
                f"Sretan krštenjedan {profile.first_name or current_user.full_name} "
                f"{profile.last_name or ''}"
            ).strip()

    start_dt = datetime(today.year, today.month, today.day, 0, 0)
    end_dt = datetime(today.year, today.month, today.day, 23, 59, 59)

    events_today = (
        db.query(Event)
        .filter(Event.start_time >= start_dt, Event.start_time <= end_dt)
        .order_by(Event.start_time)
        .all()
    )

    return TodayInfo(
        today=today,
        birthday=birthday_msg,
        baptism=baptism_msg,
        events=events_today,
    )


@app.get("/members", response_model=List[MemberProfileRead], tags=["members"])
def list_members(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return db.query(MemberProfile).all()


@app.post("/members", response_model=MemberProfileRead, tags=["members"])
def create_member_profile(
    profile_in: MemberProfileCreate,
    current_user: User = Depends(require_role("animator", "council", "admin")),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == profile_in.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    profile = MemberProfile(
        user_id=profile_in.user_id,
        formation_level=profile_in.formation_level,
        service=profile_in.service,
        talents=profile_in.talents,
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


@app.get("/events", response_model=List[EventRead], tags=["events"])
def list_events(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return db.query(Event).order_by(Event.start_time).all()


@app.post("/events", response_model=EventRead, tags=["events"])
def create_event(
    event_in: EventCreate,
    current_user: User = Depends(require_role("animator", "council", "admin")),
    db: Session = Depends(get_db),
):
    event = Event(**event_in.dict())
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


@app.get(
    "/formation-materials",
    response_model=List[FormationMaterialRead],
    tags=["formation"],
)
def list_formation_materials(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return db.query(FormationMaterial).order_by(
        FormationMaterial.created_at.desc()
    ).all()


@app.post(
    "/formation-materials",
    response_model=FormationMaterialRead,
    tags=["formation"],
)
def create_formation_material(
    material_in: FormationMaterialCreate,
    current_user: User = Depends(require_role("animator", "council", "admin")),
    db: Session = Depends(get_db),
):
    material = FormationMaterial(**material_in.dict())
    db.add(material)
    db.commit()
    db.refresh(material)
    return material


@app.get("/polls", response_model=List[PollRead], tags=["polls"])
def list_polls(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return db.query(Poll).filter(Poll.is_active == True).all()  # noqa: E712


@app.post("/polls", response_model=PollRead, tags=["polls"])
def create_poll(
    poll_in: PollCreate,
    current_user: User = Depends(require_role("animator", "council", "admin")),
    db: Session = Depends(get_db),
):
    poll = Poll(
        question=poll_in.question,
        is_multi_choice=poll_in.is_multi_choice,
    )
    db.add(poll)
    db.flush()

    for text in poll_in.options:
        option = PollOption(poll_id=poll.id, text=text)
        db.add(option)

    db.commit()
    db.refresh(poll)
    return poll


@app.post("/polls/vote", tags=["polls"])
def vote(
    poll_vote: PollVoteCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    poll = db.query(Poll).filter(Poll.id == poll_vote.poll_id).first()
    if not poll or not poll.is_active:
        raise HTTPException(status_code=404, detail="Poll not found or inactive")

    option = db.query(PollOption).filter(
        PollOption.id == poll_vote.option_id,
        PollOption.poll_id == poll_vote.poll_id,
    ).first()
    if not option:
        raise HTTPException(status_code=404, detail="Option not found in this poll")

    vote_obj = PollVote(
        poll_id=poll_vote.poll_id,
        option_id=poll_vote.option_id,
        user_id=current_user.id,
    )
    db.add(vote_obj)
    db.commit()
    return {"status": "ok"}


# INSTAGRAM – vraća zadnje 4 objave (profil kristovavojska)
@app.get(
    "/instagram",
    response_model=List[InstagramPostRead],
    tags=["instagram"],
)
def list_instagram_posts(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    posts = (
        db.query(InstagramPost)
        .order_by(InstagramPost.timestamp.desc())
        .limit(4)
        .all()
    )
    return posts


@app.get("/", tags=["health"])
def health_check():
    return {"status": "ok", "message": "Community API is running"}
