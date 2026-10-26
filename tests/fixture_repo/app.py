import sqlite3
from flask import request


def get_user(name):
    cur = sqlite3.connect("db.sqlite").cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return cur.fetchall()


def handler():
    return get_user(request.args.get("name"))


def count_users():
    cur = sqlite3.connect("db.sqlite").cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    return cur.fetchone()
