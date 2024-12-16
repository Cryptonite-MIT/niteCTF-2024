from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def load_rockyou(wordlist_path):
    """Load rockyou wordlist into memory."""
    with open(wordlist_path, "r", encoding="latin-1") as file:
        return file.read().splitlines()


def bruteforce_aes256(cipher_text, variable_one, wordlist_path):
    """Bruteforce AES-256 password from rockyou list."""
    key_part = variable_one[:16].encode(
        'utf-8')

    iv = variable_one[-16:].encode('utf-8')

    passwords = load_rockyou(wordlist_path)

    for password in passwords:
        try:
            password_bytes = password.encode('utf-8')
            key = key_part + password_bytes

            if len(key) != 32:
                continue

            cipher = AES.new(key, AES.MODE_CBC, iv)

            decrypted = cipher.decrypt(cipher_text)

            decrypted_text = unpad(decrypted, AES.block_size).decode('utf-8')

            if decrypted_text.startswith("nite"):
                print(f"Password found: {password}")
                print(f"Decrypted text: {decrypted_text}")
                return
        except (ValueError, UnicodeDecodeError):
            continue

    print("Password not found in the provided wordlist.")


if __name__ == "__main__":
    variable_one = "nite1ka4_a9b3d7f5e2c8f4a1b0d6e3c2b7a5d9e8c1f4b2a6c3d7f0e5b"
    aes256_hash = bytes.fromhex(
        "873D4ED9009DB439101E14FAE9328F5A543EAE647B467F16D10523BD9CBEE3A89AA0F7A5E73F8B9509BB35B90F512346")

    wordlist_path = "rockyou.txt"

    bruteforce_aes256(aes256_hash, variable_one, wordlist_path)
