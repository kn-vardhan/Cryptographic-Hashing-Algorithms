# Cryptographic Hashing Algorithms

A Python-based project with implementations of majorly used cryptographic hashing algorithms extended with an interactive system.

## Table of Contents

- [Introduction](#introduction)
- [Implementation Details](#implementation-details)
- [Features](#features)
- [Project Structure](#project-structure)
- [Disclaimer](#disclaimer)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)


## Introduction

Welcome to the User Authentication System, a project designed to provide a secure and customizable authentication mechanism for user accounts. This project leverages various hashing algorithms to ensure the confidentiality of user passwords and integrates seamlessly with an SQLite database.

## Implementation Details

**Pure Python Implementation:**
This user authentication system is developed using basic Python, and it does not rely on external modules for its core functionality. All components, including hashing algorithms and database handling, are implemented natively in Python. This choice ensures a lightweight and self-contained solution without external dependencies.

**Key Points:**
- **Transparency:** The absence of external modules promotes transparency in the codebase, allowing users to inspect and understand every aspect of the implementation.
- **Customization:** Users have the flexibility to modify and extend the code according to their specific requirements, leveraging the simplicity of the pure Python implementation.

Feel free to explore the code, understand its workings, and adapt it to your needs confidently.


## Features

- **Flexible Hashing Algorithms:** Choose from a variety of hashing algorithms such as SHA-256, SHA-512, HMAC-SHA256, HMAC-SHA512, PBKDF2-HMAC-SHA256, PBKDF2-HMAC-SHA512, and BCRYPT.
  
- **User-friendly Login Portal:** An interactive command-line interface for users to register, login, and manage their accounts.

- **Secure Password Storage:** Passwords are securely hashed before storage in the SQLite database, enhancing user account security.

- **Database Management:** Utilizes DB Browser for SQLite to facilitate easy database management.
- **Disclaimer:** Please check out the disclaimer before usage.

## Project Structure

The project is organized into several directories, each serving a specific purpose:

- **`authentication/`**: Contains modules related to user authentication.
  - `algo_selector.py`: Handles the selection of hashing algorithms.
  - `authenticate_user.py`: Manages user authentication and account operations.
  - `sql.py`: Provides an SQL class for handling database operations.

- **`constants/`**: Holds constant values and configurations.
  - `Constants.py`: Defines constants used throughout the project.

- **`hashing/`**: Includes modules for various hashing algorithms.
  - `bcrypt.py`: Implementation of the bcrypt hashing algorithm.
  - `blowfish.py`: Implementation of the blowfish hashing algorithm.
  - `hmac_sha2.py`: Implementation of HMAC with SHA-2.
  - `pbkdf2.py`: Implementation of the PBKDF2 key derivation function.
  - `sha256.py`: Implementation of the SHA-256 hashing algorithm.
  - `sha512.py`: Implementation of the SHA-512 hashing algorithm.

- **`main.py`**: The main entry point of the application.

Each directory may also include `__init__.py` files to indicate that the directory should be treated as a Python package.

## Disclaimer

**Attention Users:** Please be aware that, for security reasons, the hashing algorithms provided in this project (except SHA-256 and SHA-512) undergo fewer iterations than commonly found in online hash generators. This deliberate reduction in iterations is designed to strike a balance between security and computational efficiency for the scope of this project.

**Implications:**
- While SHA-256 and SHA-512 provide highly secure hash functions, others might produce different results compared to online generators.
- Reduced iterations are intentional and catered to the specific needs of this user authentication system.

**Usage Consideration:**
- If you are adopting this project for your use case, ensure you understand and accept the implications of the chosen hashing algorithms.

Remember that security requirements may vary across applications, and it's crucial to align your choices with your specific needs.


## Getting Started

### Prerequisites

- Python (3.7 and above)
- DB Browser for SQLite

### Installation

1. Clone the repository:

   ```zsh
   git clone https://github.com/kn-vardhan/cryptographic-hashing-algorithms.git
   ```

2. Database setup:
   
   Install DB Browser for SQLite from [official website](https://sqlitebrowser.org/dl/).
   
## Usage

1. Run the main program file
```zsh
   python3 main.py
```
2. Follow the prompts to choose a hashing algorithm and interact with the user login portal


