"""
Posts & Threat News Router — NKAT AI Security Platform
-------------------------------------------------------
Provides API endpoints for platform news posts, photo/video media uploads, and security advisory management.
"""

import os
import uuid
from typing import List, Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import Post

router = APIRouter(prefix="/api/v1/posts", tags=["Posts & News"])

# Project root directory for media uploads
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
UPLOAD_DIR = os.path.join(PROJECT_ROOT, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


class PostCreate(BaseModel):
    title: str
    tag: Optional[str] = "ANNOUNCEMENT"
    tag_color: Optional[str] = "#00f0ff"
    author: Optional[str] = "Admin Security Ops"
    read_time: Optional[str] = "3 min read"
    image_url: Optional[str] = None
    video_url: Optional[str] = None
    snippet: str
    content: Optional[str] = None


class PostResponse(BaseModel):
    id: int
    title: str
    tag: str
    tag_color: str
    author: str
    read_time: str
    image_url: Optional[str] = None
    video_url: Optional[str] = None
    snippet: str
    content: Optional[str] = None
    created_at: Optional[str] = None


DEFAULT_POSTS = [
    {
        "title": "CISA KEV Sync: Critical Web Application Vulnerabilities Cataloged",
        "tag": "ZERO-DAY ALERT",
        "tag_color": "#ef4444",
        "author": "NKAT Security Intelligence Labs",
        "read_time": "5 min read",
        "image_url": "/news/post1.jpg",
        "video_url": None,
        "snippet": "Our autonomous threat engine synchronized 14 newly cataloged CVE vulnerabilities affecting public web endpoints. Learn how machine learning triage isolates true exploit vectors.",
        "content": "Full advisory report on CISA KEV synchronization and predictive ML vector analysis..."
    },
    {
        "title": "Enforcing Target Ownership: Why DNS TXT & HTTP Checks are Mandatory",
        "tag": "TARGET VERIFICATION",
        "tag_color": "#00f0ff",
        "author": "Compliance Engineering Team",
        "read_time": "4 min read",
        "image_url": "/news/post2.jpg",
        "video_url": None,
        "snippet": "Discover how mandatory target verification tokens guarantee strict legal authorization, prevent unauthorized external scanning, and satisfy corporate compliance.",
        "content": "Technical specifications for target domain ownership verification procedures..."
    },
    {
        "title": "Eliminating Alert Fatigue: XGBoost Scoring for SQLi & XSS Vectors",
        "tag": "ML TRIAGE ENGINE",
        "tag_color": "#a855f7",
        "author": "AI Threat Research Group",
        "read_time": "6 min read",
        "image_url": "/news/post3.jpg",
        "video_url": None,
        "snippet": "Traditional vulnerability tools flood teams with false positives. Here is how predictive ML models evaluate payload context to prioritize high-confidence findings.",
        "content": "Detailed breakdown of the CSIC 2010 HTTP traffic dataset and XGBoost F1 performance..."
    },
    {
        "title": "Automating OWASP Top 10 & CWE Mapping for Instant PDF Audits",
        "tag": "EXECUTIVE REPORTING",
        "tag_color": "#10b981",
        "author": "Product Security Operations",
        "read_time": "3 min read",
        "image_url": "/news/post4.jpg",
        "video_url": None,
        "snippet": "Transforming raw scan telemetry into executive-ready PDF audit reports mapped to standard compliance frameworks reduces quarterly auditing overhead by 90%.",
        "content": "Overview of automated PDF generation, NIST reference mapping, and CWE categorization..."
    }
]


def seed_default_posts_if_empty(db: Session):
    count = db.query(Post).count()
    if count == 0:
        for p in DEFAULT_POSTS:
            db_post = Post(**p)
            db.add(db_post)
        db.commit()


@router.post("/upload-media")
async def upload_media_file(file: UploadFile = File(...)):
    """
    Allows admins to upload photo (image) or video files for threat advisories and news posts.
    """
    allowed_exts = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp4", ".webm", ".mov", ".m4v"}
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in allowed_exts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type '{ext}'. Allowed extensions: {', '.join(allowed_exts)}"
        )

    unique_filename = f"{uuid.uuid4().hex}{ext}"
    file_path = os.path.join(UPLOAD_DIR, unique_filename)

    with open(file_path, "wb") as buffer:
        content = await file.read()
        buffer.write(content)

    file_url = f"/uploads/{unique_filename}"
    return {
        "status": "success",
        "url": file_url,
        "filename": unique_filename,
        "media_type": "video" if ext in {".mp4", ".webm", ".mov", ".m4v"} else "image"
    }


@router.get("", response_model=List[PostResponse])
@router.get("/", response_model=List[PostResponse])
def get_all_posts(db: Session = Depends(get_db)):
    """
    Returns all published platform news posts and threat advisories.
    """
    seed_default_posts_if_empty(db)
    posts = db.query(Post).order_by(Post.id.desc()).all()
    return [
        PostResponse(
            id=p.id,
            title=p.title,
            tag=p.tag,
            tag_color=p.tag_color,
            author=p.author,
            read_time=p.read_time,
            image_url=p.image_url,
            video_url=p.video_url,
            snippet=p.snippet,
            content=p.content,
            created_at=str(p.created_at)[:19] if p.created_at else None
        )
        for p in posts
    ]


@router.post("", response_model=PostResponse, status_code=status.HTTP_201_CREATED)
@router.post("/", response_model=PostResponse, status_code=status.HTTP_201_CREATED)
def create_post(post_in: PostCreate, db: Session = Depends(get_db)):
    """
    Creates a new platform news post or security advisory with photos/videos (Admin control).
    """
    db_post = Post(
        title=post_in.title.strip(),
        tag=post_in.tag.strip() if post_in.tag else "ANNOUNCEMENT",
        tag_color=post_in.tag_color.strip() if post_in.tag_color else "#00f0ff",
        author=post_in.author.strip() if post_in.author else "Admin Security Ops",
        read_time=post_in.read_time.strip() if post_in.read_time else "3 min read",
        image_url=post_in.image_url.strip() if post_in.image_url else None,
        video_url=post_in.video_url.strip() if post_in.video_url else None,
        snippet=post_in.snippet.strip(),
        content=post_in.content.strip() if post_in.content else None
    )
    db.add(db_post)
    db.commit()
    db.refresh(db_post)
    return PostResponse(
        id=db_post.id,
        title=db_post.title,
        tag=db_post.tag,
        tag_color=db_post.tag_color,
        author=db_post.author,
        read_time=db_post.read_time,
        image_url=db_post.image_url,
        video_url=db_post.video_url,
        snippet=db_post.snippet,
        content=db_post.content,
        created_at=str(db_post.created_at)[:19] if db_post.created_at else None
    )


@router.post("/{post_id}", response_model=PostResponse)
@router.put("/{post_id}", response_model=PostResponse)
def update_post(post_id: int, post_in: PostCreate, db: Session = Depends(get_db)):
    """
    Updates an existing platform news post including photos and video URLs.
    Supports both POST and PUT HTTP methods for universal compatibility across web proxies.
    """
    seed_default_posts_if_empty(db)
    db_post = db.query(Post).filter(Post.id == post_id).first()
    if not db_post:
        raise HTTPException(status_code=404, detail=f"Post with ID {post_id} not found")

    db_post.title = post_in.title.strip()
    if post_in.tag: db_post.tag = post_in.tag.strip()
    if post_in.tag_color: db_post.tag_color = post_in.tag_color.strip()
    if post_in.author: db_post.author = post_in.author.strip()
    if post_in.read_time: db_post.read_time = post_in.read_time.strip()
    db_post.image_url = post_in.image_url.strip() if post_in.image_url else None
    db_post.video_url = post_in.video_url.strip() if post_in.video_url else None
    db_post.snippet = post_in.snippet.strip() if post_in.snippet else post_in.title.strip()
    if post_in.content: db_post.content = post_in.content.strip()

    db.commit()
    db.refresh(db_post)
    return PostResponse(
        id=db_post.id,
        title=db_post.title,
        tag=db_post.tag,
        tag_color=db_post.tag_color,
        author=db_post.author,
        read_time=db_post.read_time,
        image_url=db_post.image_url,
        video_url=db_post.video_url,
        snippet=db_post.snippet,
        content=db_post.content,
        created_at=str(db_post.created_at)[:19] if db_post.created_at else None
    )


@router.delete("/{post_id}")
def delete_post(post_id: int, db: Session = Depends(get_db)):
    """
    Deletes a news post or security advisory.
    """
    seed_default_posts_if_empty(db)
    db_post = db.query(Post).filter(Post.id == post_id).first()
    if not db_post:
        raise HTTPException(status_code=404, detail=f"Post with ID {post_id} not found")

    db.delete(db_post)
    db.commit()
    return {"status": "success", "message": f"Post #{post_id} deleted successfully"}
