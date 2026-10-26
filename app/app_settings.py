"""Settings administrators change in the app, kept in the app_settings table as "<group>.<name>" rows."""
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .db import AppSetting


def load(db: Session, group: str) -> dict[str, str]:
    rows = db.scalars(select(AppSetting).where(AppSetting.key.like(f"{group}.%"))).all()
    return {r.key.removeprefix(f"{group}."): r.value for r in rows}


def save(db: Session, group: str, values: dict[str, str]):
    for name, value in values.items():
        db.merge(AppSetting(key=f"{group}.{name}", value=value))
    db.commit()


def clear(db: Session, group: str):
    db.execute(delete(AppSetting).where(AppSetting.key.like(f"{group}.%")))
    db.commit()
