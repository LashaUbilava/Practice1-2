# Соответствие требований (12.md) реализациям в коде (11.py)

Ниже перечислены ключевые требования из `12.md` и указаны места в `11.py`, где они реализованы.

- **Защита от обхода путей (Path Traversal)** — проверка, что путь остаётся внутри корневого каталога:

```48:63:d:\projecty\Practice1-2\1 практика\11.py
def safe_resolve_join(base: Path, *parts: str) -> Path:
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
```

- **Ограничение размеров файлов / лимит загрузки и сохранения** — константы конфигурации:

```33:38:d:\projecty\Practice1-2\1 практика\11.py
# --- Конфигурация -----------------------------------------------------------------
BASE_DIR = Path("sandbox").resolve()
DB_PATH = BASE_DIR / "filemgr.db"
MAX_FILE_SIZE = 10 * 1024 * 1024       # 10 MB для чтения/записи
MAX_UNCOMPRESSED_ZIP = 50 * 1024 * 1024  # 50 MB максимум при распаковке
PBKDF2_ITERS = 100_000
```

- **Атомарная запись и безопасное копирование** — запись в tmp-файл и атомарный replace:

```163:177:d:\projecty\Practice1-2\1 практика\11.py
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
```

- **CRUD-операции с защитой и лимитами** — чтение/запись/удаление с проверкой размера и использованием `safe_resolve_join`:

```180:189:d:\projecty\Practice1-2\1 практика\11.py
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
```

```192:199:d:\projecty\Practice1-2\1 практика\11.py
def write_file_safe(rel_path: str, data: bytes, user_id: Optional[int] = None) -> None:
    if len(data) > MAX_FILE_SIZE:
        raise ValueError("Data too large")
    path = safe_resolve_join(BASE_DIR, rel_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with FS_LOCK:
        atomic_write(path, data)
    log_operation("create/modify", rel_path, user_id, f"written {len(data)} bytes")
```

```202:208:d:\projecty\Practice1-2\1 практика\11.py
def delete_file_safe(rel_path: str, user_id: Optional[int] = None) -> None:
    path = safe_resolve_join(BASE_DIR, rel_path)
    if not path.exists():
        raise FileNotFoundError("File not found")
    with FS_LOCK:
        path.unlink()
    log_operation("delete", rel_path, user_id)
```

- **Предотвращение гонок (Race Conditions)** — глобальная блокировка для операций с FS (используется в read/write/delete):

```40:41:d:\projecty\Practice1-2\1 практика\11.py
# Глобальная блокировка для атомарных операций с FS
FS_LOCK = threading.Lock()
```

- **Защита от ZIP-бомб при распаковке** — подсчёт суммарного незжатого размера и проверка безопасных путей внутри архива:

```211:234:d:\projecty\Practice1-2\1 практика\11.py
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
```

- **Безопасная десериализация JSON / XML** — отказ от опасных сериализаторов и проверка DOCTYPE в XML:

```237:241:d:\projecty\Practice1-2\1 практика\11.py
def parse_json_safe(data: bytes):
    # JSON в Python не выполняет код - безопаснее, чем pickle
    text = data.decode('utf-8')
    return json.loads(text)
```

```243:249:d:\projecty\Practice1-2\1 практика\11.py
def parse_xml_safe(data: bytes):
    text = data.decode('utf-8')
    # простая защита — отклонять документы с DOCTYPE (внешние энтити)
    if "<!DOCTYPE" in text.upper():
        raise ValueError("Unsafe XML (DOCTYPE not allowed)")
    # ElementTree не обрабатывает внешние DTD по умолчанию, но дополнительная проверка полезна
    return ET.fromstring(text)
```

- **Интеграция с БД (SQLite), подготовленные запросы, схема таблиц** — инициализация схемы и параметризованные запросы:

```66:102:d:\projecty\Practice1-2\1 практика\11.py
def init_db(db_path: Path = DB_PATH) -> None:
    ensure_base_dir()
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    # использую IF NOT EXISTS, все запросы параметризованы далее
    cur.executescript(
        """
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS Users (...);
    CREATE TABLE IF NOT EXISTS Files (...);
    CREATE TABLE IF NOT EXISTS Operations (...);
    """
    )
```

- **Хранение логов операций в БД** — функция логирования `log_operation` (вставки в `Operations` и `Files`):

```137:160:d:\projecty\Practice1-2\1 практика\11.py
def log_operation(operation_type: str, filename: Optional[str], user_id: Optional[int], details: Optional[str] = None) -> None:
    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()
    file_id = None
    if filename:
        cur.execute("SELECT id FROM Files WHERE filename = ?", (filename,))
    ...
    cur.execute("INSERT INTO Operations (timestamp, operation_type, file_id, user_id, details) VALUES (?, ?, ?, ?, ?)",
                (datetime.utcnow().isoformat(), operation_type, file_id, user_id, details))
```

- **Аутентификация и хеширование паролей (PBKDF2)** — создание пользователя и проверка пароля:

```105:109:d:\projecty\Practice1-2\1 практика\11.py
def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS)
    return salt, key
```

```112:119:d:\projecty\Practice1-2\1 практика\11.py
def create_user(username: str, password: str) -> None:
    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()
    salt, pw_hash = hash_password(password)
    cur.execute("INSERT INTO Users (username, password_salt, password_hash) VALUES (?, ?, ?)",
                (username, salt, pw_hash))
```

- **Получение списка дисков / свойства FS** — простая команда списка дисков:

```252:265:d:\projecty\Practice1-2\1 практика\11.py
def list_drives() -> list:
    drives = []
    if os.name == 'nt':
        for letter in string.ascii_uppercase:
            path = f"{letter}:\\"
            if os.path.exists(path):
                drives.append(path)
    else:
        drives.append('/')
    return drives
```

---

Краткое резюме:

- Все основные требования из `12.md` присутствуют в `11.py` (см. ссылки выше).
- При желании можно расширить этот файл примерами CLI-команд или рекомендациями по усилению безопасности.


