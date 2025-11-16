# This file contains broad exceptions

try:
    x = 1 / 0
except ValueError:
    pass # This is OK

try:
    y = 1 / 0
except Exception: # VULNERABLE: Should be found
    pass

try:
    z = 1 / 0
except BaseException: # VULNERABLE: Should be found
    pass
