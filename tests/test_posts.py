import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import SessionLocal
from backend.models import Post

client = TestClient(app)

def test_posts_crud():
    # 1. Get posts (seeds default posts)
    res = client.get("/api/v1/posts")
    assert res.status_code == 200
    posts = res.json()
    assert len(posts) > 0
    first_id = posts[0]["id"]

    # 2. Update post (PUT /api/v1/posts/{id})
    update_payload = {
        "title": "Updated Test Title",
        "tag": "ZERO-DAY ALERT",
        "tag_color": "#ef4444",
        "author": "NKAT Tester",
        "read_time": "5 min read",
        "image_url": "/news/post1.jpg",
        "video_url": None,
        "snippet": "Updated test snippet context...",
        "content": "Updated content..."
    }
    put_res = client.put(f"/api/v1/posts/{first_id}", json=update_payload)
    assert put_res.status_code == 200
    updated = put_res.json()
    assert updated["title"] == "Updated Test Title"
    assert updated["author"] == "NKAT Tester"

    # 2b. Update post via POST method fallback (POST /api/v1/posts/{id})
    post_update_res = client.post(f"/api/v1/posts/{first_id}", json=update_payload)
    assert post_update_res.status_code == 200
    assert post_update_res.json()["title"] == "Updated Test Title"

    # 3. Create post (POST /api/v1/posts)
    create_payload = {
        "title": "New Advisory",
        "tag": "EXECUTIVE REPORTING",
        "tag_color": "#38bdf8",
        "author": "Security Ops",
        "read_time": "2 min read",
        "snippet": "New advisory snippet...",
        "content": "Full body text"
    }
    post_res = client.post("/api/v1/posts", json=create_payload)
    assert post_res.status_code == 201
    new_post = post_res.json()
    assert new_post["title"] == "New Advisory"

    # 4. Delete post (DELETE /api/v1/posts/{id})
    del_res = client.delete(f"/api/v1/posts/{new_post['id']}")
    assert del_res.status_code == 200
