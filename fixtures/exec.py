# This file contains dangerous functions

a = "print('running exec')"
exec(a) # VULNERABLE: Should be found

b = "user_input"
eval(b) # VULNERABLE: Should be found

