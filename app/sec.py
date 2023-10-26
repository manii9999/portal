import secrets
import string

# Define the length of the secret key (e.g., 24 characters)
key_length = 24

# Generate a random secret key
def generate_secret_key(length):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    secret_key = ''.join(secrets.choice(alphabet) for _ in range(length))
    return secret_key

# Generate a secret key of the specified length
app_secret_key = generate_secret_key(key_length)

print("Generated Secret Key:", app_secret_key)

