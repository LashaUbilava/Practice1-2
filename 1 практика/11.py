#!/usr/bin/env python3
"""Простой безопасный файловый менеджер (консольный) — реализованы
основные требования из `12.md` в упрощённой, но безопасной форме:

- безопасное базовое хранилище (`BASE_DIR`) и защита от обхода путей;
- операции чтения/записи/удаления с ограничением размера и атомарной записью;
- безопасная работа с JSON и XML (отказ от небезопасной десериализации);
- извлечение ZIP с контролем суммарного незжатого размера (защита от ZIP-бомб);
- SQLite для хранения пользователей, файлов и операций; подготовленные запросы;
- простая аутентификация с PBKDF2-хешированием паролей;
- базовая блокировка для предотвращения race conditions.

Этот скрипт написан для учебных целей и покрывает ключевые требования из задания.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sqlite3
import string
import tempfile
import threading
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom

# --- Конфигурация -----------------------------------------------------------------
BASE_DIR = Path("sandbox").resolve()
DB_PATH = BASE_DIR / "filemgr.db"
MAX_FILE_SIZE = 10 * 1024 * 1024       # 10 MB для чтения/записи
MAX_UNCOMPRESSED_ZIP = 50 * 1024 * 1024  # 50 MB максимум при распаковке
PBKDF2_ITERS = 100_000

# Глобальная блокировка для атомарных операций с FS
FS_LOCK = threading.Lock()


def ensure_base_dir() -> None:
    BASE_DIR.mkdir(parents=True, exist_ok=True)


def safe_resolve_join(base: Path, *parts: str) -> Path:
    """Соединяет base с parts и проверяет, что результат остаётся внутри base.

    Бросает ValueError, если попытка обойти путь обнаружена.
    """
    candidate = (base.joinpath(*parts)).resolve()
    try:
        base_res = base.resolve()
    except Exception:
        base_res = base
    # защитим от случая, когда base_res не заканчивается сепаратором
    base_str = str(base_res)
    cand_str = str(candidate)
    if cand_str == base_str or cand_str.startswith(base_str + os.sep):
        return candidate
    raise ValueError("Path traversal detected")


def init_db(db_path: Path = DB_PATH) -> None:
    ensure_base_dir()
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    # использую IF NOT EXISTS, все запросы параметризованы далее
    cur.executescript(
        """
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS Users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_salt BLOB NOT NULL,
        password_hash BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS Files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        size INTEGER,
        location TEXT,
        owner_id INTEGER,
        FOREIGN KEY(owner_id) REFERENCES Users(id)
    );
    CREATE TABLE IF NOT EXISTS Operations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        operation_type TEXT,
        file_id INTEGER,
        user_id INTEGER,
        details TEXT,
        FOREIGN KEY(file_id) REFERENCES Files(id),
        FOREIGN KEY(user_id) REFERENCES Users(id)
    );
    """
    )
    conn.commit()
    conn.close()


def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS)
    return salt, key


def create_user(username: str, password: str) -> None:
    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()
    salt, pw_hash = hash_password(password)
    cur.execute("INSERT INTO Users (username, password_salt, password_hash) VALUES (?, ?, ?)",
                (username, salt, pw_hash))
    conn.commit()
    conn.close()


def authenticate(username: str, password: str) -> Optional[int]:
    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()
    cur.execute("SELECT id, password_salt, password_hash FROM Users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    user_id, salt, pw_hash = row[0], row[1], row[2]
    _, derived = hash_password(password, salt)
    if derived == pw_hash:
        return user_id
    return None


def log_operation(operation_type: str, filename: Optional[str], user_id: Optional[int], details: Optional[str] = None) -> None:
    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()
    file_id = None
    if filename:
        cur.execute("SELECT id FROM Files WHERE filename = ?", (filename,))
        r = cur.fetchone()
        if r:
            file_id = r[0]
        else:
            # insert into Files minimal record
            path = str((BASE_DIR / filename).resolve())
            size = None
            try:
                size = (BASE_DIR / filename).stat().st_size
            except Exception:
                size = None
            cur.execute("INSERT INTO Files (filename, size, location, owner_id) VALUES (?, ?, ?, ?)",
                        (filename, size, path, user_id))
            file_id = cur.lastrowid
    cur.execute("INSERT INTO Operations (timestamp, operation_type, file_id, user_id, details) VALUES (?, ?, ?, ?, ?)",
                (datetime.utcnow().isoformat(), operation_type, file_id, user_id, details))
    conn.commit()
    conn.close()


def atomic_write(target_path: Path, data: bytes) -> None:
    # write to temp file then atomic replace
    ensure_base_dir()
    fd, tmp = tempfile.mkstemp(dir=str(target_path.parent))
    os.close(fd)
    try:
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, str(target_path))
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


def read_file_safe(rel_path: str) -> bytes:
    path = safe_resolve_join(BASE_DIR, rel_path)
    if not path.exists() or not path.is_file():
        raise FileNotFoundError("File not found")
    size = path.stat().st_size
    if size > MAX_FILE_SIZE:
        raise ValueError("File too large")
    with FS_LOCK:
        with open(path, "rb") as f:
            return f.read()


def write_file_safe(rel_path: str, data: bytes, user_id: Optional[int] = None) -> None:
    if len(data) > MAX_FILE_SIZE:
        raise ValueError("Data too large")
    path = safe_resolve_join(BASE_DIR, rel_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with FS_LOCK:
        atomic_write(path, data)
    log_operation("create/modify", rel_path, user_id, f"written {len(data)} bytes")


def delete_file_safe(rel_path: str, user_id: Optional[int] = None) -> None:
    path = safe_resolve_join(BASE_DIR, rel_path)
    if not path.exists():
        raise FileNotFoundError("File not found")
    with FS_LOCK:
        path.unlink()
    log_operation("delete", rel_path, user_id)


def extract_zip_safe(zip_rel_path: str, dest_rel_dir: str, user_id: Optional[int] = None) -> None:
    zip_path = safe_resolve_join(BASE_DIR, zip_rel_path)
    dest_dir = safe_resolve_join(BASE_DIR, dest_rel_dir)
    with zipfile.ZipFile(zip_path, 'r') as zf:
        total_uncompressed = 0
        for info in zf.infolist():
            # prevent zip paths like ../../etc/passwd
            normalized = Path(info.filename)
            if normalized.is_absolute() or str(normalized).startswith(".."):
                raise ValueError("Unsafe archive entry")
            total_uncompressed += info.file_size
            if total_uncompressed > MAX_UNCOMPRESSED_ZIP:
                raise ValueError("Archive would exceed uncompressed size limit (possible zip bomb)")
        # safe to extract, but ensure members stay within dest_dir
        for info in zf.infolist():
            member_path = dest_dir.joinpath(info.filename)
            member_path_parent = member_path.parent
            member_path_parent.mkdir(parents=True, exist_ok=True)
            # read member and write atomically
            with zf.open(info) as src:
                data = src.read()
            safe_target_rel = os.path.relpath(str(member_path), str(BASE_DIR))
            write_file_safe(safe_target_rel, data, user_id=user_id)
    log_operation("extract_zip", zip_rel_path, user_id, f"extracted to {dest_rel_dir}")


def parse_json_safe(data: bytes):
    # JSON в Python не выполняет код - безопаснее, чем pickle
    text = data.decode('utf-8')
    return json.loads(text)


def parse_xml_safe(data: bytes):
    text = data.decode('utf-8')
    # простая защита — отклонять документы с DOCTYPE (внешние энтити)
    if "<!DOCTYPE" in text.upper():
        raise ValueError("Unsafe XML (DOCTYPE not allowed)")
    # ElementTree не обрабатывает внешние DTD по умолчанию, но дополнительная проверка полезна
    return ET.fromstring(text)


def list_drives() -> list:
    drives = []
    if os.name == 'nt':
        for letter in string.ascii_uppercase:
            path = f"{letter}:\\"
            if os.path.exists(path):
                try:
                    stat = os.statvfs(path) if hasattr(os, 'statvfs') else None
                except Exception:
                    stat = None
                drives.append(path)
    else:
        drives.append('/')
    return drives


def interactive_create_json(rel_path: str) -> None:
    """Интерактивно собрать JSON по ключ-значение и сохранить в файл внутри BASE_DIR.

    Для завершения ввода — нажмите Enter на пустой строке в поле ключа.
    """
    print("Введите пары key:value — для окончания нажмите Enter на пустом ключе. Значение может быть JSON-литералом (число, true/false, массив, объект) или строкой.")
    obj = {}
    while True:
        # Нажмите Enter на пустом ключе, чтобы завершить ввод
        key = input("Ключ (Enter — закончить): ").strip()
        if key == "":
            break
        raw = input("Значение (JSON или текст): ")
        # попытка распарсить значение как JSON literal, иначе строка
        try:
            val = json.loads(raw)
        except Exception:
            val = raw
        obj[key] = val
    data = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    write_file_safe(rel_path, data)
    print(f"JSON сохранён в {rel_path}")


def interactive_read_json(rel_path: str) -> None:
    try:
        raw = read_file_safe(rel_path)
    except Exception as e:
        print("Ошибка чтения:", e)
        return
    try:
        obj = parse_json_safe(raw)
    except Exception as e:
        print("Ошибка парсинга JSON:", e)
        return
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def interactive_create_xml(rel_path: str) -> None:
    """Интерактивно собрать простой XML и сохранить в файл внутри BASE_DIR.

    Поддерживается добавление элементов в корень. Для вложенности используйте путь через '/'
    в имени тега (например: user/name).
    """
    root_name = input("Root element name: ").strip()
    if not root_name:
        print("Root name required")
        return
    root = ET.Element(root_name)
    print("Введите пары tag_path:value (пустой tag — закончить). tag_path может содержать '/' для вложенности.")
    while True:
        tag = input("Tag (enter to finish): ").strip()
        if tag == "":
            break
        val = input("Value: ")
        # создаём элементы по пути
        parts = [p for p in tag.split('/') if p]
        parent = root
        for p in parts[:-1]:
            found = parent.find(p)
            if found is None:
                found = ET.SubElement(parent, p)
            parent = found
        ET.SubElement(parent, parts[-1]).text = val
    # сериализуем и отформатируем
    raw = ET.tostring(root, encoding='utf-8')
    pretty = minidom.parseString(raw).toprettyxml(encoding='utf-8')
    write_file_safe(rel_path, pretty)
    print(f"XML сохранён в {rel_path}")


def interactive_read_xml(rel_path: str) -> None:
    try:
        raw = read_file_safe(rel_path)
    except Exception as e:
        print("Ошибка чтения:", e)
        return
    try:
        # безопасная проверка через parse_xml_safe
        root = parse_xml_safe(raw)
    except Exception as e:
        print("Ошибка парсинга XML:", e)
        return
    # pretty print
    try:
        raw_bytes = ET.tostring(root, encoding='utf-8')
        pretty = minidom.parseString(raw_bytes).toprettyxml(indent='  ')
        print(pretty)
    except Exception:
        # fallback
        print(ET.tostring(root, encoding='utf-8').decode('utf-8', errors='replace'))


def interactive_menu() -> None:
    """Простейшее консольное меню — выбор опций по цифрам/буквам."""
    while True:
        print("\n=== Файловый менеджер — меню ===")
        print("1) Инициализировать БД")
        print("2) Создать пользователя")
        print("3) Записать текстовый файл")
        print("4) Прочитать файл")
        print("5) Удалить файл")
        print("6) Создать JSON (интерактивно — Enter на пустом ключе завершает)")
        print("7) Прочитать JSON (pretty)")
        print("x) Создать XML (интерактивно)")
        print("v) Прочитать XML (pretty)")
        print("8) Извлечь ZIP")
        print("9) Список дисков")
        print("q) Выход")
        choice = input("Выберите пункт: ").strip().lower()
        try:
            if choice == '1':
                init_db()
                print('DB initialized')
            elif choice == '2':
                u = input('username: ').strip()
                p = input('password: ').strip()
                create_user(u, p)
                print('User created')
            elif choice == '3':
                path = input('rel path (inside sandbox): ').strip()
                text = input('Text: ')
                write_file_safe(path, text.encode('utf-8'))
                print('Written')
            elif choice == '4':
                path = input('rel path: ').strip()
                try:
                    data = read_file_safe(path)
                    print(data.decode('utf-8', errors='replace'))
                except Exception as e:
                    print('Error:', e)
            elif choice == '5':
                path = input('rel path: ').strip()
                try:
                    delete_file_safe(path)
                    print('Deleted')
                except Exception as e:
                    print('Error:', e)
            elif choice == '6':
                path = input('rel path for JSON (e.g. data/config.json): ').strip()
                interactive_create_json(path)
            elif choice == '7':
                path = input('rel path for JSON: ').strip()
                interactive_read_json(path)
            elif choice == 'x':
                path = input('rel path for XML (e.g. data/config.xml): ').strip()
                interactive_create_xml(path)
            elif choice == 'v':
                path = input('rel path for XML: ').strip()
                interactive_read_xml(path)
            elif choice == '8':
                z = input('zip rel path: ').strip()
                dest = input('dest rel dir: ').strip()
                try:
                    extract_zip_safe(z, dest)
                    print('Extracted')
                except Exception as e:
                    print('Error:', e)
            elif choice == '9':
                for d in list_drives():
                    print(d)
            elif choice == 'q':
                break
            else:
                print('Unknown choice')
        except Exception as e:
            print('Unhandled error:', e)


def main() -> None:
    parser = argparse.ArgumentParser(description='Simple secure file manager (demo)')
    sub = parser.add_subparsers(dest='cmd')

    sub.add_parser('initdb')

    p_user = sub.add_parser('create-user')
    p_user.add_argument('username')
    p_user.add_argument('password')

    p_read = sub.add_parser('read')
    p_read.add_argument('path')

    p_write = sub.add_parser('write')
    p_write.add_argument('path')
    p_write.add_argument('text')

    p_del = sub.add_parser('delete')
    p_del.add_argument('path')

    p_zip = sub.add_parser('extract-zip')
    p_zip.add_argument('zip_path')
    p_zip.add_argument('dest_dir')

    p_info = sub.add_parser('drives')
    sub.add_parser('menu')

    args = parser.parse_args()
    if args.cmd == 'initdb':
        init_db()
        print('DB initialized at', DB_PATH)
        return

    # ensure DB exists for other ops
    init_db()

    if args.cmd == 'create-user':
        create_user(args.username, args.password)
        print('User created')
        return

    if args.cmd == 'drives':
        for d in list_drives():
            print(d)
        return

    if args.cmd == 'menu':
        interactive_menu()
        return

    if args.cmd == 'read':
        data = read_file_safe(args.path)
        print(data.decode('utf-8', errors='replace'))
        return

    if args.cmd == 'write':
        write_file_safe(args.path, args.text.encode('utf-8'))
        print('Written')
        return

    if args.cmd == 'delete':
        delete_file_safe(args.path)
        print('Deleted')
        return

    if args.cmd == 'extract-zip':
        extract_zip_safe(args.zip_path, args.dest_dir)
        print('Extracted')
        return

    parser.print_help()


if __name__ == '__main__':
    main()


