#!/usr/bin/env python3
# codul TOTP curent dintr-un secret base32 (RFC 6238, la fel ca proto/src/totp.rs)
# doar pentru teste - in folosire reala codul vine de pe telefon
#   python3 scripts/totp.py <secret_base32>

import base64
import hashlib
import hmac
import struct
import sys
import time

secret = sys.argv[1].strip().upper()
key = base64.b32decode(secret + "=" * (-len(secret) % 8))
now = int(time.time())
digest = hmac.new(key, struct.pack(">Q", now // 30), hashlib.sha1).digest()
offset = digest[19] & 0x0F
code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
print(f"{code:06d}  (valabil inca {30 - now % 30}s)")
