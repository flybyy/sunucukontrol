#!/usr/bin/env python3
import getpass
from argon2 import PasswordHasher
password = getpass.getpass('Panel şifresi: ')
if len(password) < 12:
    raise SystemExit('En az 12 karakter kullanın')
print(PasswordHasher().hash(password))
