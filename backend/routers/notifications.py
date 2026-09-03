"""
Notifications Router — API endpoints for managing in-app notifications.
Supports listing, marking read, and deleting security alerts.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import InAppNotification
from backend.schemas import NotificationResponse, NotificationMarkRead
from backend.auth import verify_api_key

router = APIRouter(prefix="/api/v1", tags=["In-App Notifications"])


@router.get("/notifications", response_model=List[NotificationResponse])
def list_notifications(
    unread_only: bool = False,
    limit: int = 50,
    auth_context: dict = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """
    Retrieves in-app security notifications for the authenticated user's organization.
    Filter by unread_only=true to view unread alerts.
    """
    org_id = auth_context.get("organization_id", 1)
    query = db.query(InAppNotification).filter(InAppNotification.organization_id == org_id)

    if unread_only:
        query = query.filter(InAppNotification.is_read == False)

    notifications = query.order_by(InAppNotification.created_at.desc()).limit(limit).all()
    return notifications


@router.patch("/notifications/{notification_id}/read", response_model=NotificationResponse)
def mark_notification_read(
    notification_id: int,
    body: Optional[NotificationMarkRead] = None,
    auth_context: dict = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """
    Marks a specific in-app notification as read.
    """
    org_id = auth_context.get("organization_id", 1)
    notif = db.query(InAppNotification).filter(
        InAppNotification.id == notification_id,
        InAppNotification.organization_id == org_id
    ).first()

    if not notif:
        raise HTTPException(status_code=404, detail=f"Notification with ID {notification_id} not found.")

    notif.is_read = body.is_read if body is not None else True
    db.commit()
    db.refresh(notif)
    return notif


@router.post("/notifications/read-all", status_code=status.HTTP_200_OK)
def mark_all_notifications_read(
    auth_context: dict = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """
    Marks all in-app notifications as read for the user's organization.
    """
    org_id = auth_context.get("organization_id", 1)
    db.query(InAppNotification).filter(
        InAppNotification.organization_id == org_id,
        InAppNotification.is_read == False
    ).update({"is_read": True}, synchronize_session=False)

    db.commit()
    return {"status": "success", "message": "All notifications marked as read."}


@router.delete("/notifications/{notification_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_notification(
    notification_id: int,
    auth_context: dict = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """
    Deletes an in-app notification record.
    """
    org_id = auth_context.get("organization_id", 1)
    notif = db.query(InAppNotification).filter(
        InAppNotification.id == notification_id,
        InAppNotification.organization_id == org_id
    ).first()

    if not notif:
        raise HTTPException(status_code=404, detail=f"Notification with ID {notification_id} not found.")

    db.delete(notif)
    db.commit()
    return None
