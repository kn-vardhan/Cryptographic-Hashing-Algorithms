# import necessary libraries
from authentication.algo_selector import AlgorithmSelector


def main():

    try:
        # Prompting user to choose a hashing algorithm
        print("Please select the hashing algorithm:\n")
        print("1. SHA-256")
        print("2. SHA-512")
        print("3. HMAC-SHA256")
        print("4. HMAC-SHA512")
        print("5. PBKDF2-HMAC-SHA256")
        print("6. PBKDF2-HMAC-SHA512")
        print("7. BCRYPT\n")

        choice = input("Enter your choice: ")
        if choice not in ['1', '2', '3', '4', '5', '6', '7']:
            raise ValueError("Invalid choice!")

    except ValueError:
        print("Invalid choice!\n")
        print("Exiting...")
        exit()

    # Creating AlgorithmSelector object to run the program
    algorithm_selector = AlgorithmSelector(choice)
    print("Hashing Algorithm Chosen:", algorithm_selector.hashing_algorithm)
    print("\n")


# Driver code
if __name__ == '__main__':
    main()
