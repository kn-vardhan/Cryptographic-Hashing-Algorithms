# import necessary libraries
import sqlite3

# import necessary constants from constants package
from constants.Constants import DATABASE_FILE
from constants.Constants import DATABASE_COLUMN_USERNAME
from constants.Constants import DATABASE_COLUMN_HASH
from constants.Constants import DATABASE_COLUMN_SALT


class SQL:
    """
    Class for handling all SQL queries using sqlite3

    Attributes:
        connection (sqlite3.Connection): connection to the database
        username (str): column name for username in the database table
        hash (str): column name for hash value in the database table
        salt (str): column name for salt in the database table

    Constructor:
        __init__(): initialize connection to the database and set column names

    Destructor:
        __del__(): close connection to the database

    Methods:
        create_table(table_name): create table if not exists
        check_username(username): check if username exists
        get_hash(username): get hash value of the username
        get_salt(username): get salt of the username
        insert(username, hash_value): insert username and hash value into table
        update(username, hash_value): update hash value of the username
        delete(username): delete username and hash value from table
    """

    def __init__(self, algorithm_name: str):
        """
        Constructor for SQL class
        Initializing a SQL object and connecting to the database
        """
        self.connection = sqlite3.connect(DATABASE_FILE)
        self.username = DATABASE_COLUMN_USERNAME
        self.hash = DATABASE_COLUMN_HASH
        self.salt = DATABASE_COLUMN_SALT
        self.create_table(algorithm_name)

    def __del__(self):
        """
        Destructor for SQL class
        Closing the SQL object's connection to the database
        """
        if self.connection:
            self.connection.close()

    def create_table(self, table_name: str):
        """
        Create a table in the database if it does not exist
        """

        query = f"""CREATE TABLE IF NOT EXISTS {table_name} (
                {self.username} VARCHAR(255) PRIMARY KEY,
                {self.hash} CHAR (128) NOT NULL,
                {self.salt} CHAR (128) NOT NULL
                )"""

        cursor = self.connection.cursor()
        cursor.execute(query)
        self.connection.commit()
        cursor.close()

    def check_username(self, table_name: str, username: str) -> bool:
        """
        Checks if the given username exists in the database table

        Args:
            table_name (str): table to check
            username (str): username to check

        Returns:
            bool: True if username exists, False otherwise
        """

        query = f"""SELECT * FROM {table_name} WHERE {self.username} = ?"""
        cursor = self.connection.cursor()
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        cursor.close()
        return True if result else False

    def get_hash(self, table_name: str, username: str) -> str:
        """
        Gets the hash value of the given username from the database table

        Args:
            table_name (str): table to check
            username (str): username to get hash value

        Returns:
            str: hash value of the username
        """

        query = f"""SELECT {self.hash} FROM {table_name}
                WHERE {self.username} = ?"""
        cursor = self.connection.cursor()
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        cursor.close()
        return result[0] if result else None

    def get_salt(self, table_name: str, username: str) -> str:
        """
        Gets the random salt of the given username from the database table

        Args:
            table_name (str): table to check
            username (str): username to get salt

        Returns:
            str: salt of the username
        """

        query = f"""SELECT {self.salt} FROM {table_name}
                WHERE {self.username} = ?"""
        cursor = self.connection.cursor()
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        cursor.close()
        return result[0] if result else None

    def insert(self, table_name: str, username: str, hash_value: str, salt: str) -> None:
        """
        Inserts the given username and hash value into the database table

        Args:
            table_name (str): table to check
            username (str): username to insert
            hash_value (str): hash value to insert
            salt (str): salt to insert

        Returns:
            None
        """

        query = f"""INSERT INTO {table_name} ({self.username},
                {self.hash}, {self.salt}) VALUES (?, ?, ?)"""
        cursor = self.connection.cursor()
        cursor.execute(query, (username, hash_value, salt))
        self.connection.commit()
        cursor.close()

    def update(self, table_name: str, username: str, hash_value: str, salt: str) -> None:
        """
        Updates the hash value of the given username in the database table

        Args:
            table_name (str): table to check
            username (str): username to update
            hash_value (str): hash value to update
            salt (str): salt to update

        Returns:
            None
        """

        query = f"""UPDATE {table_name} SET {self.hash} = ?, {self.salt} = ?
                WHERE {self.username} = ?"""
        cursor = self.connection.cursor()
        cursor.execute(query, (hash_value, salt, username))
        self.connection.commit()
        cursor.close()

    def delete(self, table_name: str, username: str) -> None:
        """
        Deletes the given username and hash value from the database table

        Args:
            table_name (str): table to check
            username (str): username to delete

        Returns:
            None
        """

        query = f"""DELETE FROM {table_name} WHERE {self.username} = ?"""
        cursor = self.connection.cursor()
        cursor.execute(query, (username,))
        self.connection.commit()
        cursor.close()
