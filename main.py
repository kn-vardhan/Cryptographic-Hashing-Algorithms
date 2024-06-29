"""
This is the main file to run the application.

It initializes all the necessary objects and starts the program.
Based on user interaction, the program proceeds to different controllers.

The program is divided into 4 controllers:
    - AlgorithmSelector: To select the hashing algorithm
    - AuthenticateUser: To authenticate the user
    - SQL: To interact with the database
    - UserInteractionChoiceSelector: To select the user interaction choice

"""

# import necessary libraries
from controllers.algo_selector import AlgorithmSelector
from controllers.authenticate_user import AuthenticateUser
from controllers.sql import SQL
from controllers.user_interaction import UserInteractionChoiceSelector


def main():
    """
    main function to run the program
    """

    # Initializing UserInteraction object
    interaction = UserInteractionChoiceSelector()

    # Initializing AlgorithmSelector object
    algorithm_selector = AlgorithmSelector(interaction)
    hashing_algorithm = algorithm_selector.hashing_algorithm
    
    # Initializing SQL object client with hashing algorithm
    sql_client = SQL(hashing_algorithm)

    # Initializing AuthenticateUser object with SQL object client
    user = AuthenticateUser(interaction, sql_client, choice=hashing_algorithm)

    # Authenticating the user
    user.authenticate_user()


# Driver code
if __name__ == '__main__':
    main()
