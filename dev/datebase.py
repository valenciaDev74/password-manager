import os

# create database
database = os.path.exists("passwords.csv")

if not database:
    with open("passwords.csv", "w") as f:
        f.write("account,username,password\n")


class Database:
    def get_passwords_by_account(self, account: str) -> dict[str, str] | None:
        with open("passwords.csv", "r") as f:
            lines = f.readlines()
            users: dict[str, str] = {}
            for line in lines[1:]:
                acc, user, pwd = line.strip().split(",")
                if acc == account:
                    users[user] = pwd
            return users
        return None


if __name__ == "__main__":
    # create database
    pass
