import sqlite3 as sql
import os

basedir = os.path.abspath(os.path.dirname(__file__))
DB_FILE_NAME = os.path.join(basedir, '../database.db')
SQL_FILE = os.path.join(basedir, 'schema.sql')

def dbConnection():
    con = sql.connect(DB_FILE_NAME)
    return con

def createDatabase():
    if not os.path.isfile(DB_FILE_NAME):
        con = sql.connect(DB_FILE_NAME)
        con.cursor().executescript(open(SQL_FILE, "r").read())
        con.commit()
        con.close()