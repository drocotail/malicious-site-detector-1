from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from app.auth.jwt_handler import get_current_user, get_optional_user
from app.database import get_db
from app.models.post import Post
from app.models.user import User

router = APIRouter(prefix="/api/posts", tags=["posts"])


class PostCreate(BaseModel):
    title: str
    content: str


class PostUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None


def _to_response(post: Post, db: Session) -> dict:
    user = db.query(User).filter(User.id == post.user_id).first()
    return {
        "id": post.id,
        "title": post.title,
        "content": post.content,
        "user_id": post.user_id,
        "author_nickname": (user.nickname or user.email.split("@")[0]) if user else "탈퇴한 사용자",
        "view_count": post.view_count,
        "created_at": post.created_at.isoformat(),
        "updated_at": post.updated_at.isoformat() if post.updated_at else None,
    }


@router.get("")
def list_posts(skip: int = 0, limit: int = 20, db: Session = Depends(get_db)):
    posts = db.query(Post).order_by(Post.created_at.desc()).offset(skip).limit(limit).all()
    return [_to_response(p, db) for p in posts]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_post(
    body: PostCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not body.title.strip():
        raise HTTPException(status_code=400, detail="제목을 입력해주세요.")
    if not body.content.strip():
        raise HTTPException(status_code=400, detail="내용을 입력해주세요.")

    post = Post(title=body.title.strip(), content=body.content.strip(), user_id=current_user.id)
    db.add(post)
    db.commit()
    db.refresh(post)
    return _to_response(post, db)


@router.get("/{post_id}")
def get_post(post_id: int, db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    post.view_count += 1
    db.commit()
    return _to_response(post, db)


@router.put("/{post_id}")
def update_post(
    post_id: int,
    body: PostUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    if post.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="수정 권한이 없습니다.")

    if body.title is not None:
        post.title = body.title.strip()
    if body.content is not None:
        post.content = body.content.strip()
    db.commit()
    db.refresh(post)
    return _to_response(post, db)


@router.delete("/{post_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_post(
    post_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")
    if post.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="삭제 권한이 없습니다.")
    db.delete(post)
    db.commit()
