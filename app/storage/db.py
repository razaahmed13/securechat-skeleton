"""
Handles all database storage operations.

- Initializes the database and tables.
- Stores and retrieves user credentials (salted hash).
- This file is run with `python -m app.storage.db --init` to setup.
"""

import os
import sys
import mysql.connector
from mysql.connector import errorcode
from dotenv import load_dotenv

# --- Database Configuration ---

# Load environment variables from .env file
# This reads the .env file you created to get the DB credentials.
load_dotenv()

# Get database connection details from environment variables
DB_HOST = os.getenv('MYSQL_HOST', '127.0.0.1') # Default to 127.0.0.1
DB_PORT = os.getenv('MYSQL_PORT', '3306')        # Default to 3306
DB_USER = os.getenv('MYSQL_USER')
DB_PASS = os.getenv('MYSQL_PASSWORD')
DB_NAME = os.getenv('MYSQL_DATABASE')

if not all([DB_HOST, DB_PORT, DB_USER, DB_PASS, DB_NAME]):
    print("Error: One or more database environment variables are not set.")
    print("Please check your .env file.")
    sys.exit(1)

# --- SQL Queries ---

# SQL command to create the 'users' table.
# This schema is taken directly from section 2.2 of the assignment PDF.
CREATE_TABLE_QUERY = """
CREATE TABLE IF NOT EXISTS users (
    email VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL UNIQUE,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    PRIMARY KEY (email)
);
"""

# --- Main Functions ---

def init_db():
    """
    Initializes the database.
    1. Creates the database (if it doesn't exist).
    2. Creates the 'users' table (if it doesn't exist).
    """
    conn = None
    cursor = None
    try:
        # Connect to the MySQL server (without specifying a database)
        conn = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASS
        )
        cursor = conn.cursor()
        
        # Create the main database if it doesn't exist
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
        print(f"Database '{DB_NAME}' ensured.")
        
        # Switch to using the newly created database
        conn.database = DB_NAME
        
        # Create the 'users' table
        cursor.execute(CREATE_TABLE_QUERY)
        print("Table 'users' initialized successfully.")

    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Error: Access denied. Check your MYSQL_USER and MYSQL_PASSWORD in .env")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print(f"Error: Database '{DB_NAME}' does not exist and could not be created.")
        elif 2000 <= err.errno <= 2999:
             print(f"Error: Cannot connect to MySQL at {DB_HOST}:{DB_PORT}.")
             print("Is the Docker container running? (Check with 'docker ps')")
        else:
            print(f"An unexpected database error occurred: {err}")
    finally:
        # Clean up the connection and cursor
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# --- Script Execution ---

def main():
    """
    Main entry point for the script.
    Checks for the '--init' flag.
    """
    # This checks if the script was run with the '--init' argument
    if "--init" in sys.argv:
        print("Initializing database...")
        init_db()
    else:
        print("This script is used to manage the database.")
        print("Run with '--init' to create the database and tables.")

# This __name__ == "__main__" block is what allows the script
# to be run directly from the command line.
if __name__ == "__main__":
    main()