"""The security team an administrator picks from a GitLab group; posted analyses can be assigned to all of them."""
import json

from sqlalchemy.orm import Session

from . import app_settings

GROUP = "security_team"


def team(db: Session) -> dict:
    """{"group": GitLab group path, "group_id": int | None, "members": [{id, username, name}]}"""
    raw = app_settings.load(db, GROUP)
    try:
        members = json.loads(raw.get("members") or "[]")
    except ValueError:
        members = []
    group_id = raw.get("group_id") or ""
    return {"group": raw.get("group", ""), "group_id": int(group_id) if group_id.isdigit() else None,
            "members": members}


def save_team(db: Session, group: str, group_id: int | None, members: list[dict]):
    if not members:
        app_settings.clear(db, GROUP)
        return
    app_settings.save(db, GROUP, {"group": group, "group_id": str(group_id or ""), "members": json.dumps(
        [{"id": m["id"], "username": m["username"], "name": m.get("name") or m["username"]} for m in members])})
