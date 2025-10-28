# Примеры запуска и использования `11.py`

Требования: установлен Python 3.8+; текущая рабочая папка — `Practice1-2/1 практика`.

Перейдите в папку проекта (PowerShell):

```powershell
cd "D:\projecty\Practice1-2\1 практика"
```

1) Инициализация базы данных

```powershell
python .\11.py initdb
# => DB initialized at sandbox\filemgr.db
```

2) Создать пользователя (пример)

```powershell
python .\11.py create-user alice S3cur3P@ss
# => User created
```

3) Записать текст в файл (путь внутри `sandbox/`)

```powershell
python .\11.py write "notes/hello.txt" "Привет, мир"
# => Written
```

4) Прочитать файл

```powershell
python .\11.py read "notes/hello.txt"
# => Привет, мир
```

5) Удалить файл

```powershell
python .\11.py delete "notes/hello.txt"
# => Deleted
```

6) Список доступных дисков

```powershell
python .\11.py drives
# => C:\, D:\, ... (на Windows)
```

7) Извлечь ZIP из `sandbox` в поддиректорию внутри `sandbox`

Пример: поместите `archive.zip` в `sandbox/` (или создайте его):

```powershell
# Создать test.zip из папки sandbox\testfolder
Compress-Archive -Path .\sandbox\testfolder\* -DestinationPath .\sandbox\archive.zip

# Затем извлечь
python .\11.py extract-zip "archive.zip" "extracted_dir"
# => Extracted
```

Советы и отладка

- Если Python не найден, укажите полный путь: `C:\Python39\python.exe .\11.py initdb`.
- Все операции с файлами происходят внутри защищённой папки `sandbox/`. Указывайте относительные пути как в примерах.
- Если путь или имя содержат пробелы, берите аргументы в кавычки.
- Для использования в Linux/macOS команды такие же, но с `python3` и путями POSIX:

```bash
cd ~/projecty/Practice1-2/1\ практика
python3 ./11.py initdb
```

Полная последовательность (рекомендуемая):

1. `python .\11.py initdb`
2. `python .\11.py create-user alice S3cur3P@ss`
3. `python .\11.py write "notes/hello.txt" "First note"`
4. `python .\11.py read "notes/hello.txt"`

Если хотите, могу добавить готовый PowerShell-скрипт, который выполняет всю последовательность автоматически. Напишите, хотите ли вы это. 


