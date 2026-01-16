import json
import os
import getpass
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DB = "passwords.json"


def get_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def load_key():  # pyright: ignore[reportUnknownParameterType]
    if not os.path.exists(DB):
        print("No password database found. Creating a new one.")
        password = getpass.getpass("Enter your master password: ")
        salt = os.urandom(16)
        key = get_key(password, salt)
        f = Fernet(key)
        validation = f.encrypt(b"DAMIAN")

        data = {  # pyright: ignore[reportUnknownVariableType]
            "salt": base64.b64encode(salt).decode(),
            "validation": base64.b64encode(validation).decode(),
            "passwords": [],
        }

        with open(DB, "w") as file:
            json.dump(data, file)

        return key, data  # pyright: ignore[reportUnknownVariableType]
    else:
        with open(DB, "r") as file:
            data = json.load(file)
            password = getpass.getpass("Enter your password: ")
            salt = base64.b64decode(data["salt"])
            validation = base64.b64decode(data["validation"])
            key = get_key(password, salt)
            f = Fernet(key)
            if f.decrypt(validation) != b"DAMIAN":
                print("Invalid password. Please try again.")
                return
            return key, data  # pyright: ignore[reportUnknownVariableType]
    return None, None  # pyright: ignore[reportUnknownVariableType]


def main() -> None:
    key, data = load_key()

    if key is None or data is None:
        return

    cipher_suite = Fernet(key)

    while True:
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
                data["passwords"].append(
                    {
                        "account": account,
                        "username": username,
                        "password": encrypted_password.decode(),
                    }
                )
                with open(DB, "w") as file:
                    json.dump(data, file)
            case 2:
                search = input("Buscar cuenta: ")
                for entry in data["passwords"]:
                    if search in entry["account"]:
                        dec_pwd = cipher_suite.decrypt(
                            entry["password"].encode()
                        ).decode()
                        print(
                            f"Found: {entry['account']} | {entry['username']} | {dec_pwd}"
                        )
            case 3:
                print("change password")
                account = input("Enter account: ")
                username = input("Enter username: ")
                password = getpass.getpass("Enter new password: ")
                encrypted_password = cipher_suite.encrypt(password.encode())
                for i, entry in enumerate(data["passwords"]):
                    if entry["account"] == account and entry["username"] == username:
                        data["passwords"][i]["password"] = encrypted_password.decode()
                        break
                with open(DB, "w") as file:
                    json.dump(data, file)
            case 4:
                print("Exit")
                exit()
            case _:
                # handle any other integer choices (non-exhaustive handling)
                print("Invalid choice")


if __name__ == "__main__":
    main()
