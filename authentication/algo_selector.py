# import necessary libraries
from authentication.sql import SQL
from authentication.authenticate_user import AuthenticateUser

# import necessary constants from constants package
from constants.Constants import SHA256, SHA512, HMAC_SHA256, HMAC_SHA512
from constants.Constants import PBKDF2_HMAC_SHA256, PBKDF2_HMAC_SHA512, BCRYPT


class AlgorithmSelector:
    """
    Class for selecting the hashing algorithm and starting the program

    Attributes:
        hashing_algorithm (str): hashing algorithm chosen by the user
        SQL_client (SQL): SQL object client for handling all SQL queries

    Constructor:
        __init__(choice): set up hashing algorithm choice, SQL object client

    Methods:
        _select_algorithm(choice): select hashing algorithm
        _setup(): setup SQL object client and authenticate user
    """

    def __init__(self, choice: str) -> None:
        """
        Constructor for AlgorithmSelector class
        Initializing an AlgorithmSelector object with hashing algorithm choice
        And initializing SQL object client

        Args:
            choice (str): hashing algorithm choice

        Returns:
            None
        """
        self.hashing_algorithm = self._select_algorithm(choice)
        self._setup()

    @staticmethod
    def _select_algorithm(choice: str) -> str:
        """
        Select hashing algorithm from user input

        Args:
            choice (str): hashing algorithm choice

        Returns:
            str: hashing algorithm chosen by the user
        """

        if choice == '1':
            return SHA256
        elif choice == '2':
            return SHA512
        elif choice == '3':
            return HMAC_SHA256
        elif choice == '4':
            return HMAC_SHA512
        elif choice == '5':
            return PBKDF2_HMAC_SHA256
        elif choice == '6':
            return PBKDF2_HMAC_SHA512
        elif choice == '7':
            return BCRYPT
        else:
            raise ValueError("Invalid choice!")

    def _setup(self) -> None:
        """
        Setup SQL object client, Authenticate User client
        Setup user authentication methods in Call Stack

        Returns:
            None
        """

        self.SQL_client = SQL(self.hashing_algorithm)
        user = AuthenticateUser(self.SQL_client, choice=self.hashing_algorithm)
        user.authenticate_user()
