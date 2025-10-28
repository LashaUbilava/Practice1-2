import os
import sys
import sqlite3
import hashlib
import hmac
import secrets
import json
import xml.etree.ElementTree as ET
import zipfile
from getpass import getpass
from datetime import datetime

# Simple secure file manager console app
ROOT_DIR = os.path.abspath("sandbox")  # restricted root for all file ops
DB_PATH = os.path.join(ROOT_DIR, "filemgr.db")
MAX_EXTRACTED_SIZE = 50 * 1024 * 1024  # 50 MB total extracted

os.makedirs(ROOT_DIR, exist_ok=True)

# --- Database setup ---
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        created_at TEXT,
        size INTEGER,
        location TEXT,
        owner_id INTEGER,
        FOREIGN KEY(owner_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS operations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        operation_type TEXT,
        file_id INTEGER,
        user_id INTEGER,
        details TEXT,
        FOREIGN KEY(file_id) REFERENCES files(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    ''')
    conn.commit()
    conn.close()

# --- Auth ---
def hash_password(password: str, salt: bytes = None) -> str:
    # PBKDF2 with SHA256
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)
    return salt.hex() + ':' + dk.hex()

def register_user(username: str, password: str) -> bool:
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        ph = hash_password(password)
        cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, ph))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def verify_password(stored: str, provided: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split(':')
    except Exception:
        return False
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(dk_hex)
    actual = hashlib.pbkdf2_hmac('sha256', provided.encode('utf-8'), salt, 100_000)
    return hmac.compare_digest(expected, actual)


def authenticate(username: str, password: str):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    uid, pw_hash = row
    return uid if verify_password(pw_hash, password) else None

# --- Utilities ---
def safe_join(root: str, *paths: str) -> str:
    # Prevent path traversal: join and ensure within root
    final = os.path.abspath(os.path.join(root, *paths))
    if os.path.commonpath([final, root]) != root:
        raise ValueError("Path traversal detected")
    return final

def log_operation(user_id, op_type, file_id=None, details=None):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO operations (timestamp, operation_type, file_id, user_id, details) VALUES (?, ?, ?, ?, ?)",
        (datetime.utcnow().isoformat(), op_type, file_id, user_id, details))
    conn.commit()
    conn.close()

# --- File operations ---
def list_drives_and_stats():
    # cross-platform: show root dir usage and free space
    stat = os.statvfs(ROOT_DIR)
    total = stat.f_frsize * stat.f_blocks
    free = stat.f_frsize * stat.f_bavail
    print(f"Root sandbox: {ROOT_DIR}")
    print(f"Total bytes: {total}  Free bytes: {free}")

def list_files(rel_dir=""):
    path = safe_join(ROOT_DIR, rel_dir)
    for name in os.listdir(path):
        full = os.path.join(path, name)
        print(name, '<DIR>' if os.path.isdir(full) else os.path.getsize(full))

def read_text_file(rel_path):
    path = safe_join(ROOT_DIR, rel_path)
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return f.read()

def write_text_file(rel_path, content, owner_id=None):
    path = safe_join(ROOT_DIR, rel_path)
    dirpath = os.path.dirname(path)
    os.makedirs(dirpath, exist_ok=True)
    # atomic write: write to temp file then rename
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(content)
    os.replace(tmp, path)
    size = os.path.getsize(path)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO files (filename, created_at, size, location, owner_id) VALUES (?, ?, ?, ?, ?)",
                (os.path.basename(path), datetime.utcnow().isoformat(), size, path, owner_id))
    fid = cur.lastrowid
    conn.commit(); conn.close()
    return fid

def delete_file(rel_path):
    path = safe_join(ROOT_DIR, rel_path)
    if os.path.isdir(path):
        raise IsADirectoryError("Target is a directory")
    # remove atomically: unlink
    os.remove(path)
    # try to remove file record from DB if exists
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM files WHERE location = ?", (path,))
        conn.commit()
        conn.close()
    except Exception:
        pass

# --- JSON / XML safe handling ---
def safe_load_json(rel_path):
    path = safe_join(ROOT_DIR, rel_path)
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def safe_load_xml(rel_path):
    path = safe_join(ROOT_DIR, rel_path)
    # Use ElementTree which doesn't execute code
    tree = ET.parse(path)
    return tree.getroot()

# --- ZIP handling with limits ---
def safe_extract_zip(rel_path, dest_rel):
    zpath = safe_join(ROOT_DIR, rel_path)
    dest = safe_join(ROOT_DIR, dest_rel)
    with zipfile.ZipFile(zpath, 'r') as zf:
        total_uncompressed = 0
        for zi in zf.infolist():
            # guard against suspicious entries
            if zi.filename.endswith('/'):
                continue
            total_uncompressed += zi.file_size
            if total_uncompressed > MAX_EXTRACTED_SIZE:
                raise ValueError('Extraction would exceed allowed size')
            # ensure each member path is safe
            member_target = safe_join(dest, zi.filename)
            if not member_target.startswith(dest):
                raise ValueError('Zip contains disallowed paths')
        zf.extractall(dest)

# --- CLI ---
def main_menu(user_id):
    while True:
        print('\n1) List files  2) Read file  3) Write file  4) Delete file  5) Load JSON  6) Load XML  7) Extract ZIP  0) Logout')
        choice = input('> ').strip()
        try:
            if choice == '1':
                list_files('')
            elif choice == '2':
                p = input('relative path: ')
                print(read_text_file(p))
            elif choice == '3':
                p = input('relative path: ')
                print('Enter content, end with EOF (Ctrl+D/Ctrl+Z):')
                content = sys.stdin.read()
                fid = write_text_file(p, content, owner_id=user_id)
                log_operation(user_id, 'create', file_id=fid, details=p)
                print('Written')
                return
            elif choice == '4':
                p = input('relative path: ')
                delete_file(p)
                log_operation(user_id, 'delete', details=p)
                print('Deleted')
            elif choice == '5':
                p = input('relative path: ')
                data = safe_load_json(p)
                print(json.dumps(data, indent=2, ensure_ascii=False))
            elif choice == '6':
                p = input('relative path: ')
                root = safe_load_xml(p)
                print(ET.tostring(root, encoding='unicode'))
            elif choice == '7':
                p = input('zip path: ')
                d = input('dest relative dir: ')
                safe_extract_zip(p, d)
                log_operation(user_id, 'extract_zip', details=p)
                print('Extracted')
            elif choice == '0':
                break
            else:
                print('unknown')
        except Exception as e:
            print('Error:', e)

if __name__ == '__main__':
    init_db()
    print('Secure File Manager (sandboxed to', ROOT_DIR, ')')
    while True:
        print('\n1) Register 2) Login 0) Exit')
        cmd = input('> ').strip()
        if cmd == '1':
            u = input('username: ').strip()
            pw = getpass('password: ')
            ok = register_user(u, pw)
            print('Registered' if ok else 'User exists')
        elif cmd == '2':
            u = input('username: ').strip()
            pw = getpass('password: ')
            uid = authenticate(u, pw)
            if uid:
                print('Welcome', u)
                main_menu(uid)
            else:
                print('Invalid credentials')
        elif cmd == '0':
            break
        else:
            print('unknown')
