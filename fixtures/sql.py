# This file contains SQL injection vulnerabilities

name = "admin"

# VULNERABLE: f-string concatenation
query1 = f"SELECT * FROM users WHERE name = '{name}'" 

# VULNERABLE: '+' concatenation
query2 = "SELECT * FROM users WHERE pass = '" + name + "'"

# This is the safe, parameterized way (should NOT be found)
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
