# import necessary libraries
from typing import List
from hashing.sha256 import sha256
from hashing.sha512 import sha512
from hashing.hmac_sha2 import hmac_sha2
from hashing.pbkdf2 import pbkdf2
from hashing.bcrypt import bcrypt

# import necessary constants from constants package
from constants.Constants import SHA256, SHA512, HMAC_SHA256, HMAC_SHA512
from constants.Constants import PBKDF2_HMAC_SHA256, PBKDF2_HMAC_SHA512
from constants.Constants import PBKDF2_ITERATIONS, PBKDF2_DK_LEN
from constants.Constants import PBKDF2_H_LEN_SHA256, PBKDF2_H_LEN_SHA512
from constants.Constants import BCRYPT, BCRYPT_COST, HMAC_SHA2_KEY


class AuthenticateUser:
    """
    Class for authenticating user, performing operations on the user's account

    Attributes:
        sql (SQL): SQL object client for handling all SQL queries
        choice (str): hashing algorithm chosen by the user

    Constructor:
        __init__(sql_client, choice): set up SQL object client algorithm choice

    Methods:
        authenticate_user(username): perform operations on the user's account
        register_user(): register user in the database
        login_user(): login user in the database
        _change_password(username): change password of the user in the database
        _delete_account(username): delete account of the user from the database
        __execute_hashing(password): execute hashing algorithm on the password
    """

    def __init__(self, sql_client, choice: str):
        """
        Constructor for AuthenticateUser class
        Initializing an AuthenticateUser object with SQL object client
        And initializing hashing algorithm choice
        """

        self.sql = sql_client
        self.choice = choice
        print(f'Welcome to {self.choice} hashing algorithm!\n')
        print("An interactive user login portal will be displayed below.\n")

    def authenticate_user(self, username=None) -> None:
        """
        Authenticating user and performing operations on the user's account

        Args:
            username (str) or None: username of the user; default is None

        Returns:
            None
        """

        # If username is None, then the user is not logged in
        if username is None:
            print("1. Register")
            print("2. Login")
            print("3. Exit\n")

            # User choice of operation
            # try:
            choice = int(input("Enter your choice: "))
            if choice == 1:
                self.register_user()
            elif choice == 2:
                self.login_user()
            elif choice == 3:
                print("Exiting...\n")
                exit()
            else:
                print("Invalid choice!\n")
                self.authenticate_user()

            # Handling invalid choice
            # except ValueError:
            #     print("Invalid choice!\n")
            #     self.authenticate_user()

        # If username is not None, then the user is logged in
        else:
            print("1. Change Password")
            print("2. Delete Account")
            print("3. Sign Out\n")

            # User choice of operation
            try:
                choice = int(input("Enter your choice: "))
                if choice == 1:
                    self._change_password(username)
                elif choice == 2:
                    self._delete_account(username)
                elif choice == 3:
                    print("Signed out successfully!\n")
                    self.authenticate_user()
                else:
                    print("Invalid choice!\n")
                    self.authenticate_user(username=username)

            # Handling invalid choice
            except ValueError:
                print("Invalid choice!\n")
                self.authenticate_user(username=username)

    def register_user(self) -> None:
        """
        Registering user in the database along with username, hash, and salt

        Returns:
            None
        """

        username = input("Enter username: ")

        # Checking if username already exists in the database
        while self.sql.check_username(self.choice, username):
            print("Username already exists!\n")
            username = input("Enter username: ")

        password = input("Create password: ")
        confirm_password = input("Confirm password: ")

        # Checking if password and confirm password match
        while password != confirm_password:
            print("Passwords do not match!\n")
            password = input("Create password: ")
            confirm_password = input("Confirm password: ")

        # Performing hashing on the password and storing in the database
        hash_pwd, _salt = self.__execute_hashing(password)
        self.sql.insert(self.choice, username, hash_pwd, salt=_salt)

        print("Registration successful!\n")
        self.authenticate_user()

    def login_user(self) -> None:
        """
        Logging in user and performing operations on user's account

        Returns:
            None
        """

        username = input("Enter username: ")

        # Checking if username exists in the database
        while not self.sql.check_username(self.choice, username):
            print("Username does not exist!\n")
            username = input("Enter username: ")

        password = input("Enter password: ")
        _salt = self.sql.get_salt(self.choice, username)
        hash_pwd, _ = self.__execute_hashing(password, salt=_salt)

        # Checking if hashed password matches with the hash value in database
        count = 1
        while self.sql.get_hash(self.choice, username) != hash_pwd and count < 3:
            print(f'Incorrect password! {3 - count} attempts left.\n')
            password = input("Enter password: ")
            hash_pwd, _ = self.__execute_hashing(password, salt=_salt)
            count += 1

        # Many incorrect attempts by the user, exiting the registration portal
        if count == 3:
            print("Too many incorrect attempts! Exiting...\n")
            self.authenticate_user()

        print("Login successful!\n")
        self.authenticate_user(username=username)

    def _change_password(self, username: str) -> None:
        """
        Protected method:
        Changing password of the user in the database

        Args:
            username (str): username of the user

        Returns:
            None
        """

        # Prompting user for new password
        password = input("Enter new password: ")
        confirm_password = input("Confirm new password: ")

        # Checking if password and confirm password match
        while password != confirm_password:
            print("Passwords do not match!\n")
            password = input("Enter new password: ")
            confirm_password = input("Confirm new password: ")

        # Performing hashing on the password and updating in the database
        hash_pwd, _salt = self.__execute_hashing(password)
        self.sql.update(self.choice, username, hash_pwd, _salt)

        print("Password updated successfully!\n")
        self.authenticate_user(username=username)

    def _delete_account(self, username: str) -> None:
        """
        Protected method:
        Deleting account of the user from the database

        Args:
            username (str): username of the user

        Returns:
            None
        """

        print("Are you sure you want to delete your account?")
        print("1. Yes")
        print("2. No\n")

        # User choice of operation
        try:
            choice = input("Enter your choice: ")
            if choice.upper() == '1':
                self.sql.delete(self.choice, username)
                print("Account deleted successfully!\n")
                self.authenticate_user()
            elif choice.upper() == '0':
                print("Account not deleted!\n")
                self.authenticate_user(username=username)
            else:
                print("Invalid choice!\n")
                self.authenticate_user(username=username)

        # Handling invalid choice
        except ValueError:
            print("Invalid choice!\n")
            self.authenticate_user(username=username)

    def __execute_hashing(self, password: str, salt=None) -> List[str]:
        """
        Private method:
        Executing hashing algorithm on the password

        Args:
            password (str): password to hash
            salt (str): salt to hash; default is None

        Returns:
            list(str): list containing hash value and salt
        """

        # Executing specific hashing algorithm based on user's choice
        if self.choice == SHA256:
            return [sha256(password), 'NA']
        elif self.choice == SHA512:
            return [sha512(password), 'NA']
        elif self.choice == HMAC_SHA256:
            return [hmac_sha2(HMAC_SHA2_KEY, password, 256), 'NA']
        elif self.choice == HMAC_SHA512:
            return [hmac_sha2(HMAC_SHA2_KEY, password, 512), 'NA']
        elif self.choice == PBKDF2_HMAC_SHA256:
            return pbkdf2(password, 256, salt, PBKDF2_ITERATIONS, PBKDF2_H_LEN_SHA256, PBKDF2_DK_LEN)
        elif self.choice == PBKDF2_HMAC_SHA512:
            return pbkdf2(password, 512, salt, PBKDF2_ITERATIONS, PBKDF2_H_LEN_SHA512, PBKDF2_DK_LEN)
        elif self.choice == BCRYPT:
            return bcrypt(password, salt, BCRYPT_COST)
        else:
            raise ValueError("Invalid choice!")
