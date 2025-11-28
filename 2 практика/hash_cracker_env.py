#!/usr/bin/env python3
"""
Brute-force password cracker (environment-based dependencies).

This variant DOES NOT attempt to install missing packages. It requires that
`bcrypt` and `argon2-cffi` (if you plan to crack those algos) are pre-installed
in the Python interpreter you run the script with.

Usage is the same as `hash_cracker.py`.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import string
import time
from typing import Iterable, Optional
import multiprocessing

try:
    import bcrypt
except Exception:
    bcrypt = None

try:
    from argon2 import PasswordHasher
except Exception:
    PasswordHasher = None


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
    if bcrypt is None:
        raise RuntimeError('bcrypt library is not installed (pip install bcrypt)')
    return bcrypt.checkpw(candidate.encode('utf-8'), target_hash.encode('utf-8'))


def argon2_matches(candidate: str, target_hash: str) -> bool:
    if PasswordHasher is None:
        raise RuntimeError('argon2-cffi is not installed (pip install argon2-cffi)')
    ph = PasswordHasher()
    try:
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
            prefixes = [''] if length == 0 else [p for p in charset]
            tasks = []
            for prefix in prefixes:
                if len(prefix) > length:
                    continue
                tasks.append((prefix, length, charset, target_hash, algo, control))

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
    return name


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


