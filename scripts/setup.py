#!/usr/bin/env python3
"""Create a local .env with generated Argon2 credentials. Never print the password."""
import getpass
import secrets
from pathlib import Path
from argon2 import PasswordHasher
root = Path(__file__).resolve().parent.parent
out = root / '.env'
if out.exists():
    raise SystemExit('.env already exists; refusing to overwrite it')
pw = getpass.getpass('Choose admin password (minimum 12 chars): ')
if len(pw) < 12:
    raise SystemExit('Password too short')
confirm = getpass.getpass('Repeat password: ')
if pw != confirm:
    raise SystemExit('Passwords do not match')
config = (root / '.env.example').read_text(encoding='utf-8')
config = config.replace('REPLACE_WITH_ARGON2_HASH', PasswordHasher().hash(pw))
config = config.replace('REPLACE_WITH_RANDOM_SECRET', secrets.token_urlsafe(48))
out.write_text(config, encoding='utf-8')
out.chmod(0o600)
print('Created .env (mode 0600). Keep it private.')
