# This file contains safe code that should NOT trigger any rules.

# 1. Safe exception handling
try:
    x = int("test")
except ValueError:
    print("Handled correctly")

# 2. Safe string formatting
name = "User"
message = f"Hello, {name}. Welcome."
query = "SELECT * FROM users" # Not concatenated

# 3. Safe variable names
api_documentation = "key_goes_here"
secret_recipe = "flour"

# 4. Safe crypto
import hashlib
h = hashlib.sha256(b"safe")

# 5. Not exec or eval
def execute_task():
    pass
