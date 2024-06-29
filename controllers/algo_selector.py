"""
This module is responsible for selecting the hashing algorithm and starting the program.

Classes:
    AlgorithmSelector

"""

# import necessary libraries
import sys
from controllers.sql import SQL
from controllers.authenticate_user import AuthenticateUser

# import necessary constants from constants package
from constants.Constants import choices
from constants.Constants import SHA256, SHA512, HMAC_SHA256, HMAC_SHA512
from constants.Constants import PBKDF2_HMAC_SHA256, PBKDF2_HMAC_SHA512, BCRYPT


class AlgorithmSelector:
    """
    Class for selecting the hashing algorithm and starting the program

    Attributes:
        hashing_algorithm (str): hashing algorithm chosen by the user
        choice (str): hashing algorithm choice via option selection
        interaction (UserInteraction): UserInteraction object
        SQL_client (SQL): SQL object client

    Constructor:
        __init__(user_interaction): set up hashing algorithm choice using UserInteraction object

    Methods:
        exit_program(): exits the program
        _select_algorithm(choice): select hashing algorithm
        _setup(): setup SQL object client and authenticate user
    """

    def __init__(self, user_interaction):
        """
        Constructor for AlgorithmSelector class
        Dependency Injection of UserInteraction object
        Initializing an AlgorithmSelector object with UserInteraction object
        """
        self.interaction = user_interaction

        try:
            self.choice = self.interaction.get_choice("Please select the hashing algorithm:", choices)
            if self.choice not in choices.keys():
                raise ValueError("Invalid choice!")

        except ValueError:
            self.interaction.display_message("Invalid choice!\nExiting...")
            self.exit_program()

        self.hashing_algorithm = self._select_algorithm(self.choice)

    @staticmethod
    def exit_program():
        """
        Exit the program
        
        Returns:
            None
        """
        sys.exit()

    @staticmethod
    def _select_algorithm(choice: str) -> str:
        """
        Select hashing algorithm from user input

        Args:
            choice (str): hashing algorithm choice

        Returns:
            str: hashing algorithm chosen by the user

        Raises:
            ValueError: Invalid choice
        """

        algorithms = {
            '1': SHA256,
            '2': SHA512,
            '3': HMAC_SHA256,
            '4': HMAC_SHA512,
            '5': PBKDF2_HMAC_SHA256,
            '6': PBKDF2_HMAC_SHA512,
            '7': BCRYPT,
        }

        try:
            return algorithms[choice]
        except KeyError:
            raise ValueError("Invalid choice!")

    def _setup(self) -> None:
        """
        Setup SQL object client, Authenticate User client
        Setup user authentication methods in Call Stack

        Returns:
            None
        """

        self.SQL_client = SQL(self.hashing_algorithm)
        user = AuthenticateUser(self.interaction, self.SQL_client, choice=self.hashing_algorithm)
        user.authenticate_user()
