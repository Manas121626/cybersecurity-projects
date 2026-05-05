import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ============================================================
#   FILE ENCRYPTION / DECRYPTION TOOL
#   Project by: [Your Name]
#   Concepts: AES Encryption, Hashing, Key Derivation (PBKDF2)
# ============================================================


def generate_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Derives a secure encryption key from a password using PBKDF2HMAC.
    This is how real-world apps generate keys from user passwords.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # 100,000 iterations = very hard to brute force
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def encrypt_file(filepath, password):
    """
    Encrypts a file using AES encryption (via Fernet).
    Saves the encrypted file as filename.encrypted
    """
    # Check if file exists
    if not os.path.exists(filepath):
        print(f"  ❌ File not found: {filepath}")
        return False

    # Generate a random salt (adds randomness to encryption)
    salt = os.urandom(16)

    # Derive encryption key from password + salt
    key = generate_key_from_password(password, salt)
    fernet = Fernet(key)

    # Read original file
    with open(filepath, 'rb') as f:
        original_data = f.read()

    # Encrypt the data
    encrypted_data = fernet.encrypt(original_data)

    # Save encrypted file (salt + encrypted data together)
    encrypted_filepath = filepath + ".encrypted"
    with open(encrypted_filepath, 'wb') as f:
        f.write(salt + encrypted_data)  # Store salt at beginning of file

    file_size_original  = len(original_data)
    file_size_encrypted = len(encrypted_data)

    print(f"\n  ✅ File encrypted successfully!")
    print(f"  Original file  : {filepath} ({file_size_original} bytes)")
    print(f"  Encrypted file : {encrypted_filepath} ({file_size_encrypted} bytes)")
    print(f"  🔑 Salt used   : {salt.hex()[:16]}... (stored inside encrypted file)")
    print(f"\n  ⚠️  Keep your password safe! Without it, the file CANNOT be decrypted.")
    return True


def decrypt_file(filepath, password):
    """
    Decrypts a previously encrypted file.
    Restores the original file.
    """
    # Check if file exists
    if not os.path.exists(filepath):
        print(f"  ❌ File not found: {filepath}")
        return False

    # Check if it's an encrypted file
    if not filepath.endswith(".encrypted"):
        print(f"  ⚠️  This file doesn't appear to be encrypted by this tool.")
        confirm = input("  Continue anyway? (y/n): ").lower()
        if confirm != 'y':
            return False

    # Read encrypted file
    with open(filepath, 'rb') as f:
        file_data = f.read()

    # Extract salt (first 16 bytes) and encrypted content
    salt           = file_data[:16]
    encrypted_data = file_data[16:]

    # Derive the same key using password + salt
    key = generate_key_from_password(password, salt)
    fernet = Fernet(key)

    # Try to decrypt
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception:
        print("\n  ❌ Decryption FAILED! Wrong password or corrupted file.")
        print("  💡 Make sure you are using the exact same password used during encryption.")
        return False

    # Save decrypted file (remove .encrypted extension)
    if filepath.endswith(".encrypted"):
        decrypted_filepath = filepath[:-len(".encrypted")]
        # Avoid overwriting original — add _decrypted if file already exists
        if os.path.exists(decrypted_filepath):
            base, ext = os.path.splitext(decrypted_filepath)
            decrypted_filepath = base + "_decrypted" + ext
    else:
        base, ext = os.path.splitext(filepath)
        decrypted_filepath = base + "_decrypted" + ext

    with open(decrypted_filepath, 'wb') as f:
        f.write(decrypted_data)

    print(f"\n  ✅ File decrypted successfully!")
    print(f"  Encrypted file : {filepath}")
    print(f"  Restored file  : {decrypted_filepath} ({len(decrypted_data)} bytes)")
    return True


def encrypt_text(text, password):
    """
    Encrypts a plain text message directly (no file needed).
    """
    salt = os.urandom(16)
    key  = generate_key_from_password(password, salt)
    fernet = Fernet(key)

    encrypted = fernet.encrypt(text.encode())
    # Combine salt + encrypted, encode to base64 for easy sharing
    result = base64.urlsafe_b64encode(salt + encrypted).decode()

    print(f"\n  ✅ Text encrypted!")
    print(f"  🔒 Encrypted Message:\n")
    print(f"  {result}")
    print(f"\n  💡 Share this encrypted message — only someone with the password can read it.")
    return result


def decrypt_text(encrypted_text, password):
    """
    Decrypts an encrypted text message.
    """
    try:
        # Decode from base64
        raw        = base64.urlsafe_b64decode(encrypted_text.encode())
        salt       = raw[:16]
        encrypted  = raw[16:]

        key    = generate_key_from_password(password, salt)
        fernet = Fernet(key)

        decrypted = fernet.decrypt(encrypted).decode()
        print(f"\n  ✅ Text decrypted!")
        print(f"  📩 Original Message: {decrypted}")
        return decrypted
    except Exception:
        print("\n  ❌ Decryption FAILED! Wrong password or invalid encrypted text.")
        return None


def hash_file(filepath):
    """
    Generates SHA-256 hash of a file.
    Used to verify file integrity — if hash changes, file was tampered.
    """
    if not os.path.exists(filepath):
        print(f"  ❌ File not found: {filepath}")
        return None

    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)

    file_hash = sha256.hexdigest()
    print(f"\n  ✅ SHA-256 Hash Generated!")
    print(f"  File : {filepath}")
    print(f"  Hash : {file_hash}")
    print(f"\n  💡 Save this hash. If the file is tampered, the hash will change.")
    return file_hash


def main():
    print("=" * 55)
    print("   🔐 FILE ENCRYPTION / DECRYPTION TOOL")
    print("=" * 55)
    print("   Uses AES-256 encryption + PBKDF2 key derivation")
    print("=" * 55)

    while True:
        print("\nWhat would you like to do?")
        print("  1. Encrypt a file")
        print("  2. Decrypt a file")
        print("  3. Encrypt a text message")
        print("  4. Decrypt a text message")
        print("  5. Generate SHA-256 hash of a file")
        print("  6. Exit")

        choice = input("\nEnter your choice (1-6): ").strip()

        # ---- Encrypt File ----
        if choice == "1":
            print("\n--- ENCRYPT FILE ---")
            filepath = input("  Enter full path of file to encrypt: ").strip()
            password = input("  Enter encryption password: ").strip()
            if not password:
                print("  ❌ Password cannot be empty.")
                continue
            encrypt_file(filepath, password)

        # ---- Decrypt File ----
        elif choice == "2":
            print("\n--- DECRYPT FILE ---")
            filepath = input("  Enter full path of encrypted file: ").strip()
            password = input("  Enter decryption password: ").strip()
            decrypt_file(filepath, password)

        # ---- Encrypt Text ----
        elif choice == "3":
            print("\n--- ENCRYPT TEXT MESSAGE ---")
            text     = input("  Enter message to encrypt: ").strip()
            password = input("  Enter encryption password: ").strip()
            if not text or not password:
                print("  ❌ Message and password cannot be empty.")
                continue
            encrypt_text(text, password)

        # ---- Decrypt Text ----
        elif choice == "4":
            print("\n--- DECRYPT TEXT MESSAGE ---")
            encrypted_text = input("  Paste encrypted message: ").strip()
            password       = input("  Enter decryption password: ").strip()
            decrypt_text(encrypted_text, password)

        # ---- Hash File ----
        elif choice == "5":
            print("\n--- SHA-256 FILE HASH ---")
            filepath = input("  Enter full path of file to hash: ").strip()
            hash_file(filepath)

        # ---- Exit ----
        elif choice == "6":
            print("\n👋 Goodbye! Keep your files secure.\n")
            break

        else:
            print("  ⚠️  Invalid choice. Please enter 1 to 6.")


if __name__ == "__main__":
    main()
