# Test file for hardcoded credentials detection

# This should be detected - OpenAI API key
openai_key = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"

# This should be detected - GitHub token
github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz123"

# This should be detected - AWS Access Key
aws_key = "AKIAIOSFODNN7EXAMPLE"

# This should be detected - JWT token
jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# This should be detected - Generic long API key
api_key = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"

# This should be detected - Direct string literal
client = SomeClient("sk-1234567890abcdefghijklmnopqrstuvwxyz")

# This should be detected - In a config dict
config = {
    "api_key": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6"
}

# This should NOT be detected - Environment variable (safe)
import os
safe_key = os.getenv("API_KEY")

# This should NOT be detected - Placeholder text
placeholder = "your_api_key_here"

# This should NOT be detected - Short string
short = "test123"
