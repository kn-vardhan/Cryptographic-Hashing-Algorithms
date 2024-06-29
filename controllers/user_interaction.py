"""
This module is responsible for user interaction.

Classes:
    UserInteraction
    UserInteractionChoiceSelector

"""


class UserInteraction:
    """
    Class for performing user i/o operations

    Methods:
        get_input(prompt): get user input
        display_message(message): print message to the user
    """

    @staticmethod
    def get_input(prompt: str) -> str:
        """
        Get user input

        Args:
            prompt (str): input message to be displayed to the user

        Returns:
            str: input given by the user
        """

        return input(prompt)

    @staticmethod
    def display_message(message: str) -> None:
        """
        Display/print message to the user

        Args:
            message (str): string of characters to be displayed

        Returns:
            None
        """

        print(message)


class UserInteractionChoiceSelector(UserInteraction):
    """
    Child Class of UserInteraction Class for selecting hashing algorithm

    Methods:
        get_choice(prompt, choices): get user choice of hashing algorithm
    """

    def get_choice(self, prompt: str, choices) -> str:
        """
        Get user choice of hashing algorithm

        Args:
            prompt (str): input message to be displayed to the user
            choices (dict): dictionary containing all available hashing algorithm options

        Returns:
            str: hashing algorithm chosen by the user
        """

        self.display_message(prompt)
        # Displaying all available hashing algorithm options
        for choice, algorithm in choices.items():
            self.display_message(f"{choice}. {algorithm}")

        return self.get_input("Enter your choice: ")
