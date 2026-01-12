import os
import getpass
from cryptography.fernet import Fernet
import bcrypt
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

cipher_suite: Fernet | None = None


def main() -> None:
    # menu

    active_password = os.path.exists("secrets.txt")

    if not active_password:
        print("please introduce password")
        password = getpass.getpass()

        with open("secrets.txt", "wb") as f:
            encrypted_pass = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            f.write(encrypted_pass)
    else:
        print("introduce password")
        password = getpass.getpass()

        with open("secrets.txt", "rb") as f:
            encrypted_pass = f.read().strip()
            is_the_pass = bcrypt.checkpw(password.encode(), encrypted_pass)
            if is_the_pass:
                print("password is correct")
                salt = b"\x12\xab..."  # Un valor fijo que guardas en tu código
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                # Esta es la llave que usas para Fernet
                llave = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                cipher_suite = Fernet(llave)
            else:
                print("password is incorrect")
                return

    print("Welcome to the Password Manager!")
    print("--------------------------------")
    print("1. Add a new password")
    print("2. get password from account")
    print("3. change password")
    print("4. Exit")

    choice: int = int(input("Enter your choice: "))
    while choice < 1 and choice > 4:
        choice = int(input("Enter a valid choice (1-4): "))

    match choice:
        case 1:
            print("Add a new password")
            account = input("Enter account: ")
            username = input("Enter username: ")
            password = getpass.getpass("Enter password: ")
            encrypted_password = cipher_suite.encrypt(password.encode())
            with open("passwords.csv", "a") as f:
                f.write(f"{account},{username},{encrypted_password.decode()}\n")
            return main()
        case 2:
            print("get password from account")
            account = input("Enter account: ")
            with open("passwords.csv", "r") as f:
                for line in f:
                    if account in line:
                        username, password = line.split(",")[1:3]
                        password = cipher_suite.decrypt(password.encode()).decode()
                        print(f"username: {username}")
                        print(f"password: {password}")
            print("Accounts searched")
            return main()
        case 3:
            print("change password")
            account = input("Enter account: ")
            username = input("Enter username: ")
            password = getpass.getpass("Enter new password: ")
            encrypted_password = cipher_suite.encrypt(password.encode())
            with open("passwords.csv", "r") as f:
                lines = f.readlines()
                for i, line in enumerate(lines):
                    if account in line:
                        lines[i] = (
                            f"{account},{username},{encrypted_password.decode()}\n"
                        )
                        break
            with open("passwords.csv", "w") as f:
                f.writelines(lines)
                return main()
        case 4:
            print("Exit")
            return

        case _:
            # handle any other integer choices (non-exhaustive handling)
            print("Invalid choice")
            return main()
    print("Hello from password-manager!")


if __name__ == "__main__":
    main()
