# EMS254 Documentation

EMS254 is a mode of payment system that enables Third Party Payments using the Escrow Model and Technology.

This is an explanation on the backend structure of the Escrow System, EMS254.


### File Structure

`EMS254/tree/main/api/v1/views/user` - This is an path that has the routes/endpoints that are handling Registration, Login, User Profile, Logout

[user_views.py](https://github.com/Bradkibs/EMS254/blob/main/api/v1/views/user/users_views.py)

#### `@app_views.route('/register', methods=['POST'])`

`Input Data Validation:`

The function retrieves user registration data from the JSON payload of an HTTP request using `request.get_json()`.

It checks if the required fields (`email`, `password`, `first_name`, `last_name`, `phone_number`, `location`) are present in the data. If any of them is missing, it returns a JSON response with a 400 status code and an appropriate error message.

`User Registration:`

It checks if a user with the provided email already exists. If so, it returns a JSON response with a 409 status code and a message indicating that the user already exists.

If the user does not exist, it proceeds to create a new user using `user_auth.create_user()` with the provided registration data.

`Account Creation:`

After creating the user, it calls `account_service.create_account()` to create a corresponding account for the user. The account is initialized with zero funds (`Total_funds`, `incomming_funds`, `outgoing_funds`), and the `user_id` is set to the ID of the newly created user.

`Response:`

It constructs a JSON response with a 201 status code (indicating successful creation) and includes information about the user and the created account.

The response includes the user ID, a success message, and details about the created account.

#### `@app_views.route('/login', methods=['POST'])`

`login_user()` - handles login requests using either an email address or a phone number as identifiers.

`Data Extraction`: The function extracts information from the JSON request data, including `email`, `phone_number`, and `password`.

`Input Validation`: The code performs basic input validation, checking whether either an `email` or a `phone_number` is provided in the request data. If neither is provided or if the `password` is missing, it returns a JSON response with an error message and a 400 HTTP status code.

`User Retrieval`: Depending on whether `email` or `phone_number` is provided, it retrieves the user using either `user_auth.get_user_by_email()` or `user_auth.get_user_by_email(phone_number)`.

`User Existence Check`: It checks if a user with the provided identifier (email or phone number) exists. If the user is not found, it returns a JSON response indicating that the user was not found with a 404 HTTP status code.


`Password Verification`: If the user is found, it verifies the provided password using `user_auth.verify_password(password, user.password)`. If the password is incorrect, it returns a JSON response indicating an invalid password with a 400 HTTP status code.

`Token Creation and Cookie Setting`: If the email or phone number and password are valid, it creates an access token using `user_authenticator.create_token(user.id)`. It then sets the access token as a cookie in the response using `user_authenticator.set_cookie(response, access_token)`.

`Response`: Finally, it returns a JSON response indicating successful login with a 200 HTTP status code.

#### `@app_views.route('/profile', methods=['GET'])`

`get_user()` - It uses a JSON Web Token (JWT) for authentication (`@jwt_required()`) and then retrieves user information based on the authenticated user's ID.

`JWT Authentication`: The function is decorated with `@jwt_required()`, indicating that a valid JWT token is required for access. The `user_id` is extracted from the authenticated token using `user_authenticator.get_authenticated_user()`.

`User Existence Check`: It checks if a user with the specified ID exists. If the user is not found, it returns a JSON response indicating that the user was not found with a 404 HTTP status code.

`Response`: If the user is found, it constructs a dictionary (user_data) containing various user attributes such as email, first name, last name, phone number, location, role, is_active, and last login. It returns this user data as a JSON response with a 200 HTTP status code.

#### `@app_views.route('/logout', methods=['POST'])`

`logout()` - It handles logout requests by extracting the access token from the 'Authorization' header, checking if the user is authenticated, and then logging them out by removing the access token


## auth

`Authentication` is Done using JWT(JSON Web Token) - JWT stands for JSON Web Token. It is a compact,
URL-safe means of representing claims to be transferred between two parties.
The claims in a JWT are encoded as a JSON object that is used as the payload of a
JSON Web Signature (JWS) structure or as the plaintext of a JSON Web Encryption (JWE) structure,
enabling the claims to be digitally signed or integrity protected with a Message Authentication Code (MAC) and/or encrypted.

[auth.py](https://github.com/Bradkibs/EMS254/blob/main/auth/auth.py) - This file enables the use of JWT Authentication,  Containing a class that allowed token creation and cookies to be set

#### `class Authentication:`

`__token` Attribute: This is a private attribute of the class used to store the access token. It's initially set to `None`.

`create_token(self, identity) Method`: This method creates a new access token using the `create_access_token` function. It takes an `identity` parameter and sets the `__token` attribute to the generated token. The token is then returned.

`refresh_token(self, identity) Method`: This method seems to be intended to refresh the token by calling `create_token` with the provided `identity`. However, it doesn't appear to be effectively refreshing the token since it doesn't update the `__token` attribute.

`validate_jwt(self) Method`: This method attempts to validate the JWT in the request using the `verify_jwt_in_request` function. If an exception occurs during the validation, it returns `False`; otherwise, it returns `True`.

`get_authenticated_user(self) Method`: This method checks if the JWT is valid using `validate_jwt`. If the JWT is valid, it retrieves and returns the identity from the token using `get_jwt_identity`. If the JWT is not valid, it returns `None`.

`set_cookie(self, response, access_token) Method`: This method sets the access token as a cookie in the provided response using `set_access_cookies`.

`unset_cookie(self, response, access_token) Method`: This method unsets (removes) the access token cookie from the provided response using `unset_jwt_cookies`.


[user_auth.py](https://github.com/Bradkibs/EMS254/blob/main/auth/user_auth.py)

#### `class UserAuth:`

`UserAuth`

It includes methods for hashing and verifying passwords, creating users, and interacting with user data in a database.

`Database Initialization`: The class has a class-level attribute `_db` that represents a database connection, and it's initialized and reloaded during the class creation.

`hash_password(self, password) Method`: This method takes a password as input, encodes it, generates a salt using `gensalt()`, hashes the password with the salt using `hashpw()`, and returns the hashed password as a UTF-8 decoded string.

`verify_password(self, candidate_password, hashed_password) Method`: This method takes a candidate password and a hashed password, compares them using `checkpw()`, and returns `True` if the passwords match, indicating a successful verification.

`create_user(self, **kwargs) Method`: This method creates a new user by taking various user details as keyword arguments, hashing the provided password using `hash_password`, creating a new `User` object, adding it to the database, and saving the changes. The method returns the created user.

`get_user_by_email(self, email) Method`: Retrieves a user from the database based on the provided email.

`get_user_by_phone_number(self, phone_number) Method`: Retrieves a user from the database based on the provided phone number.

`get_user_by_id(self, id) Method`: Retrieves a user from the database based on the provided user ID.

`get_all_users(self) Method`: Retrieves all users from the database.

`delete_user(self, id) Method`: Deletes a user from the database based on the provided user ID.

`update_user(self, id, email, password) Method`: Updates a user's email and/or password in the database based on the provided user ID. It retrieves the user, modifies the relevant fields, and saves the changes.


[verify_user.py](https://github.com/Bradkibs/EMS254/blob/main/auth/verify_user.py)

`generate_verification_token() Function`:

This function generates a URL-safe verification token using the `secrets` module. The `token_urlsafe` method generates a random URL-safe text with the specified number of bytes (16 bytes in this case).

The generated token is intended to be used as part of a verification URL sent to users for email confirmation.

`send_verification_email(user_email, verification_token) Function`:

This function sends a verification email to the specified `user_email` with a verification token.

It uses the `Mail` and `Message` classes from an email library (possibly Flask-Mail) to create and send an email.

The subject of the email is set to 'Verification Email for EMS254', and the sender is retrieved from the environment variable `VERIFICATION_EMAIL`.

The email body includes a verification URL constructed using `url_for`. The `url_for` function generates a fully qualified URL for a given endpoint (in this case, 'app_views.register') with the verification token as a parameter. The`_external=True` argument ensures that an absolute URL is generated.

The email body also includes a message instructing the recipient to click the verification link to confirm their email address for EMS254. It also provides information on what to do if they didn't register for EMS254.

The function attempts to send the email using `mail.send(msg)`. If the email is sent successfully, it returns a JSON response with a success message and status code 200. If there's an exception during the email sending process, it returns a JSON response with an error message and status code 502.

## db

[__init__.py](https://github.com/Bradkibs/EMS254/blob/main/db/__init__.py)

```
from db.storage import DB

storage = DB()
storage.reload()
```

[storage.py](https://github.com/Bradkibs/EMS254/blob/main/db/storage.py)


## models

[accounts.py](https://github.com/Bradkibs/EMS254/blob/main/models/accounts.py)

SQLAlchemy model class named `Accounts`. This class represents a table in a relational database and is likely part of an ORM (Object-Relational Mapping) system.

`Table Configuration`:

`__tablename__`: Specifies the name of the table in the database. In this case, it's set to 'accounts'.

`Columns`:

`user_id`: A foreign key column that references the 'id' column in the 'users' table. It establishes a relationship with the 'User' model.
`account_number`: A column representing the account number. It is set to be unique, indicating that each account should have a distinct account number.
`Total_funds`: A column representing the total funds associated with the account.
`incomming_funds`: A column representing incoming funds for the account.
`outgoing_funds`: A column representing outgoing funds for the account.

`Relationship`:

The `user` attribute establishes a bidirectional relationship between the 'User' and 'Accounts' models. It specifies that there is a relationship between the 'user_id' column in the 'Accounts' table and the 'id' column in the 'users' table. The relationship function is used to define this relationship.

`Constructor`:

`__init__`: The constructor initializes the object, and it calls the constructor of the superclass `(super().__init__)` with any passed arguments and keyword arguments.

[basemodel.py](https://github.com/Bradkibs/EMS254/blob/main/models/basemodel.py)


[messages.py](https://github.com/Bradkibs/EMS254/blob/main/models/messages.py)


[transactions.py](https://github.com/Bradkibs/EMS254/blob/main/models/transactions.py)


[users.py](https://github.com/Bradkibs/EMS254/blob/main/models/users.py)

### Utils

[messages.py](https://github.com/Bradkibs/EMS254/blob/main/utils/messages.py)


`MessagesService` class: This class contains methods for managing messages.

`__db` attribute: This is an instance of a DB class

`__db.reload():` This line of code is called during the initialization of the MessagesService class,
and it appears to reload the database. The exact behavior of this method depends on the implementation of the DB class.

`create_message(self, **kwargs):` This method is used to create a new message. It takes keyword arguments (`content`, `sender_id`, `receiver_id`) to create a message object, adds it to the database, and then saves the changes to the database. It returns the created message.

`get_message(self, message_id):` This method retrieves a message from the database based on its `message_id`.

`get_specific_user_messages(self, user_id):` This method retrieves all messages associated with a specific user, identified by `user_id`, from the database.

`delete_message(self, message_id):` This method deletes a message from the database based on its `message_id`.

`delete_all_user_messages(self, user_id):` This method deletes all messages associated with a specific user, identified by `user_id`, from the database.


### Transaction Logic file

[transaction_logic.py](https://github.com/Bradkibs/EMS254/blob/main/utils/transaction_logic.py)

`TransactionService class:`

- `__db attribute:` This is an instance of a DB class, representing a database connection.

- `__db.reload():` This line of code is called during the initialization of the TransactionService class, and it reloads the database.

- `create_transaction(self, **kwargs):` This method is used to create a new transaction. It takes keyword arguments (`sender_id`, `receiver_id`, `amount`) to create a `Transactions` object, adds it to the database, and then saves the changes to the database. It returns the created transaction.

- `get_transaction(self, transaction_id):` This method retrieves a transaction from the database based on its `transaction_id`.

- `view_user_specific_transactions(self, user_id):` This method retrieves all transactions where the specified user is the sender, identified by `user_id`.


### User account file

[user_account.py](https://github.com/Bradkibs/EMS254/blob/main/utils/transaction_logic.py)

`AccountService class:`

- `__db attribute:` This is an instance of a DB class, representing a database connection.

- `__db.reload():` This line of code is called during the initialization of the `AccountService class`, and it reloads the database.

- `create_account_number(self):` This method generates a random account number.

- `create_account(self, **kwargs):` This method creates a new account by generating a unique account number and checking if it already exists in the database.
If it does, a new account number is generated. The method then creates an `Accounts` object, adds it to the database, and saves the changes.

- `get_account(self, account_number):` This method retrieves an account from the database based on its account number.

- `add_total_funds(self, account_number, amount):` This method adds funds to an account's total funds.

- `transact(self, amount, sender_id, receiver_id):` This method performs a transaction by subtracting the specified amount from the sender's account and adding it to the receiver's account. It also includes error checking, such as ensuring the amount is greater than 100, checking for sender and receiver IDs, verifying sufficient funds, and handling transactions using SQL transactions (`_db.begin()`, `_db.rollback()`, and `_db.save()`).

### App

[app.py](https://github.com/Bradkibs/EMS254/blob/main/app.py)

