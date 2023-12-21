from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt_message(key, message):
    cipher = AES.new(pad(key.encode(), AES.block_size), AES.MODE_ECB)
    encrypted_key = cipher.encrypt(pad(key.encode(), AES.block_size))
    encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
    return encrypted_key, encrypted_message

def decrypt_message(key, encrypted_key, encrypted_message):
    cipher = AES.new(pad(key.encode(), AES.block_size), AES.MODE_ECB)
    decrypted_key = unpad(cipher.decrypt(encrypted_key), AES.block_size)
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)
    return decrypted_key.decode(), decrypted_message.decode()

def main():
    while True:
        print("Menu:")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        choice = input("Enter your choice (1, 2, or 3): ")

        if choice == "1":
            message = input("Enter the message to encrypt: ")
            key = input("Enter the encryption key: ")
            encrypted_key, encrypted_message = encrypt_message(key, message)
            print("Encrypted key:", encrypted_key.hex())
            print("Encrypted message:", encrypted_message.hex())
        elif choice == "2":
            encrypted_key = bytes.fromhex(input("Enter the encrypted key: "))
            encrypted_message = bytes.fromhex(input("Enter the encrypted message: "))
            key = input("Enter the decryption key: ")
            decrypted_key, decrypted_message = decrypt_message(key, encrypted_key, encrypted_message)
            print("Decrypted key:", decrypted_key)
            print("Decrypted message:", decrypted_message)
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
