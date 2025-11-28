#!/usr/bin/env python3
"""
Lightweight brute-force password cracker.

Features:
- Auto-detects MD5, SHA1, bcrypt and Argon2 hashes.
- Brute-forces using a configurable charset and max length.
- Uses multiprocessing to split work by prefix for faster search on multi-core CPUs.

Usage examples:
  python hash_cracker.py --hash e10adc3949ba59abbe56e057f20f883e --max-len 6
  python hash_cracker.py --hash "$2a$10$z4u9Z..."  # bcrypt
  python hash_cracker.py --hash "$argon2id$..." --charset digits --max-len 6

Note: defaults are conservative (digits+lowercase) so sample test hashes like "123456" will be found quickly.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import string
import time
from typing import Iterable, Optional
import multiprocessing
import importlib
import subprocess
import sys


def _ensure_import(module_name: str, package_name: str | None = None):
    """Ensure module is importable in the current Python; install package if missing.

    Uses the current interpreter (sys.executable) to run pip so no PATH/venv activation is required.
    Raises ImportError if installation/import still fails.
    """
    try:
        return importlib.import_module(module_name)
    except Exception:
        pkg = package_name or module_name
        print(f"Package '{pkg}' not found — attempting to install into current Python: {sys.executable}")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', pkg])
        except subprocess.CalledProcessError as e:
            raise ImportError(f"Failed to install package '{pkg}': {e}")
        # try import again
        return importlib.import_module(module_name)


def detect_algorithm(target_hash: str) -> str:
    if target_hash.startswith(('$2a$', '$2b$', '$2y$')):
        return 'bcrypt'
    if target_hash.startswith('$argon2'):
        return 'argon2'
    hexchars = set('0123456789abcdef')
    h = target_hash.lower()
    if len(h) == 32 and all(c in hexchars for c in h):
        return 'md5'
    if len(h) == 40 and all(c in hexchars for c in h):
        return 'sha1'
    return 'unknown'


def md5_matches(candidate: str, target_hash: str) -> bool:
    return hashlib.md5(candidate.encode('utf-8')).hexdigest() == target_hash.lower()


def sha1_matches(candidate: str, target_hash: str) -> bool:
    return hashlib.sha1(candidate.encode('utf-8')).hexdigest() == target_hash.lower()


def bcrypt_matches(candidate: str, target_hash: str) -> bool:
    bcrypt = _ensure_import('bcrypt', 'bcrypt')
    return bcrypt.checkpw(candidate.encode('utf-8'), target_hash.encode('utf-8'))


def argon2_matches(candidate: str, target_hash: str) -> bool:
    argon2 = _ensure_import('argon2', 'argon2-cffi')
    PasswordHasher = getattr(argon2, 'PasswordHasher')
    ph = PasswordHasher()
    try:
        # PasswordHasher.verify(hash, password) -> returns True or raises
        return ph.verify(target_hash, candidate)
    except Exception:
        return False


def verify(candidate: str, target_hash: str, algo: str) -> bool:
    if algo == 'md5':
        return md5_matches(candidate, target_hash)
    if algo == 'sha1':
        return sha1_matches(candidate, target_hash)
    if algo == 'bcrypt':
        return bcrypt_matches(candidate, target_hash)
    if algo == 'argon2':
        return argon2_matches(candidate, target_hash)
    raise ValueError(f'Unsupported algorithm: {algo}')


def search_prefix_task(args):
    """Worker: search all candidates that start with prefix for given total_length."""
    prefix, total_length, charset, target_hash, algo, control = args
    remaining = total_length - len(prefix)
    if remaining < 0:
        return None
    if remaining == 0:
        if control['found']:
            return None
        if verify(prefix, target_hash, algo):
            return prefix
        return None

    for tail in itertools.product(charset, repeat=remaining):
        if control['found']:
            return None
        candidate = prefix + ''.join(tail)
        if verify(candidate, target_hash, algo):
            return candidate
    return None


def crack_hash(target_hash: str,
               algo: Optional[str] = None,
               max_len: int = 6,
               charset: Iterable[str] = None,
               workers: int = None) -> Optional[str]:
    if charset is None:
        # conservative default that matches common lab passwords like 123456
        charset = list('0123456789' + string.ascii_lowercase)
    else:
        charset = list(charset)

    if workers is None:
        workers = max(1, multiprocessing.cpu_count() - 1)

    if algo is None or algo == 'auto':
        algo = detect_algorithm(target_hash)

    if algo == 'unknown':
        raise ValueError('Unable to detect algorithm from hash; specify --algo')

    manager = multiprocessing.Manager()
    control = manager.dict()
    control['found'] = False

    pool = multiprocessing.Pool(processes=workers)

    try:
        for length in range(1, max_len + 1):
            if control['found']:
                break
            # split by 1-character prefixes to distribute work
            prefixes = [''] if length == 0 else [p for p in charset]
            tasks = []
            for prefix in prefixes:
                if len(prefix) > length:
                    continue
                tasks.append((prefix, length, charset, target_hash, algo, control))

            # submit tasks
            results = [pool.apply_async(search_prefix_task, (t,)) for t in tasks]

            for r in results:
                res = r.get()
                if res:
                    control['found'] = True
                    pool.terminate()
                    return res
    finally:
        try:
            pool.close()
            pool.join()
        except Exception:
            pass

    return None


def parse_charset(name: str) -> str:
    if name == 'digits':
        return '0123456789'
    if name == 'lower':
        return string.ascii_lowercase
    if name == 'lower+digits':
        return string.digits + string.ascii_lowercase
    if name == 'alnum':
        return string.ascii_letters + string.digits
    return name  # direct charset


def main() -> None:
    parser = argparse.ArgumentParser(description='Brute-force hash cracker (MD5, SHA1, bcrypt, Argon2)')
    parser.add_argument('--hash', '-H', required=True, help='Target hash to crack')
    parser.add_argument('--algo', '-a', default='auto', help='Algorithm: auto|md5|sha1|bcrypt|argon2')
    parser.add_argument('--max-len', '-m', type=int, default=6, help='Maximum password length to try')
    parser.add_argument('--charset', '-c', default='lower+digits', help='Charset name or literal characters')
    parser.add_argument('--workers', '-w', type=int, default=None, help='Number of worker processes')
    args = parser.parse_args()

    charset = parse_charset(args.charset)
    print(f"Algorithm: {args.algo} (detected: {detect_algorithm(args.hash)})")
    print(f"Charset length: {len(charset)}; max length: {args.max_len}; workers: {args.workers}")

    start = time.time()
    try:
        found = crack_hash(args.hash, algo=args.algo, max_len=args.max_len, charset=charset, workers=args.workers)
    except Exception as e:
        print('Error:', e)
        return
    elapsed = time.time() - start

    if found:
        print(f'Found password: "{found}" (time: {elapsed:.3f}s)')
    else:
        print(f'Password not found with given parameters (time: {elapsed:.3f}s)')


if __name__ == '__main__':
    main()


