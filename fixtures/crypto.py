import hashlib

# This file contains weak crypto

data = b"my_password"

# VULNERABLE: MD5
h1 = hashlib.md5(data) 

# VULNERABLE: SHA1
h2 = hashlib.sha1(data) 

# This is OK (should NOT be found)
h3 = hashlib.sha256(data)
