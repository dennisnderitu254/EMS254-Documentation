# EMS254 Documentation

EMS254 is a mode of payment system that enables Third Party Payments using the Escrow Model and Technology.

This is an explanation on the backend structure of the Escrow System, EMS254.


### File Structure

`EMS254/tree/main/api/v1/views/user` - This is an path that has the routes/endpoints that are handling Registration, Login, User Profile, Logout

`/EMS254/blob/main/api/v1/views/transactions/` - This is a  Path that has the routes/endpoints that handle transactions

[user_views.py](https://github.com/Bradkibs/EMS254/blob/main/api/v1/views/user/users_views.py)

#### `@app_views.route('/register', methods=['POST'])`

`Input Data Validation:`

- The function retrieves user registration data from the JSON payload of an HTTP request using `request.get_json()`.

- It checks if the required fields (`email`, `password`, `first_name`, `last_name`, `phone_number`, `location`) are present in the data. If any of them is missing, it returns a JSON response with a 400 status code and an appropriate error message.

`User Registration:`

- It checks if a user with the provided email already exists. If so, it returns a JSON response with a 409 status code and a message indicating that the user already exists.

- If the user does not exist, it proceeds to create a new user using `user_auth.create_user()` with the provided registration data.

`Account Creation:`

- After creating the user, it calls `account_service.create_account()` to create a corresponding account for the user. The account is initialized with zero funds (`Total_funds`, `incomming_funds`, `outgoing_funds`), and the `user_id` is set to the ID of the newly created user.

`Response:`

- It constructs a JSON response with a 201 status code (indicating successful creation) and includes information about the user and the created account.

- The response includes the user ID, a success message, and details about the created account.

#### `@app_views.route('/login', methods=['POST'])`

- `login_user()` - handles login requests using either an email address or a phone number as identifiers.

- `Data Extraction`: The function extracts information from the JSON request data, including `email`, `phone_number`, and `password`.

- `Input Validation`: The code performs basic input validation, checking whether either an `email` or a `phone_number` is provided in the request data. If neither is provided or if the `password` is missing, it returns a JSON response with an error message and a 400 HTTP status code.

- `User Retrieval`: Depending on whether `email` or `phone_number` is provided, it retrieves the user using either `user_auth.get_user_by_email()` or `user_auth.get_user_by_email(phone_number)`.

- `User Existence Check`: It checks if a user with the provided identifier (email or phone number) exists. If the user is not found, it returns a JSON response indicating that the user was not found with a 404 HTTP status code.

- `Password Verification`: If the user is found, it verifies the provided password using `user_auth.verify_password(password, user.password)`. If the password is incorrect, it returns a JSON response indicating an invalid password with a 400 HTTP status code.

- `Token Creation and Cookie Setting`: If the email or phone number and password are valid, it creates an access token using `user_authenticator.create_token(user.id)`. It then sets the access token as a cookie in the response using `user_authenticator.set_cookie(response, access_token)`.

- `Response`: Finally, it returns a JSON response indicating successful login with a 200 HTTP status code.

#### `@app_views.route('/profile', methods=['GET'])`

- `get_user()` - It uses a JSON Web Token (JWT) for authentication (`@jwt_required()`) and then retrieves user information based on the authenticated user's ID.

- `JWT Authentication`: The function is decorated with `@jwt_required()`, indicating that a valid JWT token is required for access. The `user_id` is extracted from the authenticated token using `user_authenticator.get_authenticated_user()`.

- `User Existence Check`: It checks if a user with the specified ID exists. If the user is not found, it returns a JSON response indicating that the user was not found with a 404 HTTP status code.

- `Response`: If the user is found, it constructs a dictionary (user_data) containing various user attributes such as email, first name, last name, phone number, location, role, is_active, and last login. It returns this user data as a JSON response with a 200 HTTP status code.

#### `@app_views.route('/logout', methods=['POST'])`

- `logout()` - It handles logout requests by extracting the access token from the 'Authorization' header, checking if the user is authenticated, and then logging them out by removing the access token

### `transactions`

`/EMS254/blob/main/api/v1/views/transactions/` - This is a  Path that has the routes/endpoints that handle transactions

[transact_view.py](https://github.com/Bradkibs/EMS254/blob/main/api/v1/views/transactions/transact_view.py)

#### `@user_trans.route('/transact', methods=['POST'])`

Function - `def create_transaction():`

- Creates a new transaction in the database.
- Requires a JWT token to be passed in the Authorization header.
- Returns:
    - A JSON object containing a message and a transaction object.

The function first checks to make sure that all of the required parameters are provided. If any of the parameters are missing, the function returns an error message and a status code of 400 (Bad Request).

Next, the function retrieves the user ID of the receiver from the account number. If the receiver ID cannot be found, the function returns an error message and a status code of 400 (Bad Request).

The function then checks to make sure that the sender and receiver are not the same person. If they are, the function returns an error message and a status code of 400 (Bad Request).

Finally, the function calls the account_service.transact() method to transfer the money from the sender's account to the receiver's account. If the transaction is successful, the function creates a new transaction object in the database and returns it.

Logic Summary
1. Get the authenticated user's ID.
2. Get the account number and amount from the request body.
3. Check if the account number and amount are provided.
4. Get the receiver's ID.
5. Check if the receiver's ID is found.
6. Check if the sender's ID is the same as the receiver's ID.
7. Transfer the amount from the sender's account to the receiver's account.
8. Create a new transaction object.
9. Return a JSON object containing a message and the transaction object.

#### `@user_trans.route('/transactions', methods=['GET'])`

Function - `get_all_transactions()`
- This function gets all of the transactions for the authenticated user. It takes no parameters and returns a list of transaction objects.

The function first gets the authenticated user's ID by calling the `user_authenticator.get_authenticated_user()` method. If the user is not authenticated, the function returns `None`.

Next, the function calls the `transaction_service.get_all_transactions()` method to get all of the transactions for the authenticated user. This method takes the user's ID as a parameter and returns a list of transaction objects.

Logic Summary

* Gets all of the transactions for the authenticated user.
* Requires a JWT token to be passed in the Authorization header.
* Returns:
    - A list of transaction objects.

Function - `get_all_transactions()` Logic
1. Get the authenticated user's ID.
2. Get all of the user's transactions.
3. Return the transactions.

#### `@user_trans.route('/transaction/<int:transaction_id>', methods=['GET'])`

#### `@user_trans.route('/approve/<String:transaction_id>', methods=['PATCH'])`

#### `@user_trans.route('/cancel/<String:transaction_id>', methods=['PATCH'])`

#### `@user_trans.route('/deposit')`

#### `@user_trans.route('/withdraw')`

## `auth`

`Authentication` is Done using JWT(JSON Web Token) - JWT stands for JSON Web Token. It is a compact,
URL-safe means of representing claims to be transferred between two parties.
The claims in a JWT are encoded as a JSON object that is used as the payload of a
JSON Web Signature (JWS) structure or as the plaintext of a JSON Web Encryption (JWE) structure,
enabling the claims to be digitally signed or integrity protected with a Message Authentication Code (MAC) and/or encrypted.

[auth.py](https://github.com/Bradkibs/EMS254/blob/main/auth/auth.py) - This file enables the use of JWT Authentication,  Containing a class that allowed token creation and cookies to be set

#### `class Authentication:`

- `__token` Attribute: This is a private attribute of the class used to store the access token. It's initially set to `None`.

- `create_token(self, identity) Method`: This method creates a new access token using the `create_access_token` function. It takes an `identity` parameter and sets the `__token` attribute to the generated token. The token is then returned.

- `refresh_token(self, identity) Method`: This method seems to be intended to refresh the token by calling `create_token` with the provided `identity`. However, it doesn't appear to be effectively refreshing the token since it doesn't update the `__token` attribute.

- `validate_jwt(self) Method`: This method attempts to validate the JWT in the request using the `verify_jwt_in_request` function. If an exception occurs during the validation, it returns `False`; otherwise, it returns `True`.

- `get_authenticated_user(self) Method`: This method checks if the JWT is valid using `validate_jwt`. If the JWT is valid, it retrieves and returns the identity from the token using `get_jwt_identity`. If the JWT is not valid, it returns `None`.

- `set_cookie(self, response, access_token) Method`: This method sets the access token as a cookie in the provided response using `set_access_cookies`.

- `unset_cookie(self, response, access_token) Method`: This method unsets (removes) the access token cookie from the provided response using `unset_jwt_cookies`.


[user_auth.py](https://github.com/Bradkibs/EMS254/blob/main/auth/user_auth.py)

#### `class UserAuth:`

`UserAuth`

- It includes methods for hashing and verifying passwords, creating users, and interacting with user data in a database.

- `Database Initialization`: The class has a class-level attribute `_db` that represents a database connection, and it's initialized and reloaded during the class creation.

- `hash_password(self, password) Method`: This method takes a password as input, encodes it, generates a salt using `gensalt()`, hashes the password with the salt using `hashpw()`, and returns the hashed password as a UTF-8 decoded string.

- `verify_password(self, candidate_password, hashed_password) Method`: This method takes a candidate password and a hashed password, compares them using `checkpw()`, and returns `True` if the passwords match, indicating a successful verification.

- `create_user(self, **kwargs) Method`: This method creates a new user by taking various user details as keyword arguments, hashing the provided password using `hash_password`, creating a new `User` object, adding it to the database, and saving the changes. The method returns the created user.

- `get_user_by_email(self, email) Method`: Retrieves a user from the database based on the provided email.

- `get_user_by_phone_number(self, phone_number) Method`: Retrieves a user from the database based on the provided phone number.

- `get_user_by_id(self, id) Method`: Retrieves a user from the database based on the provided user ID.

- `get_all_users(self) Method`: Retrieves all users from the database.

- `delete_user(self, id) Method`: Deletes a user from the database based on the provided user ID.

- `update_user(self, id, email, password) Method`: Updates a user's email and/or password in the database based on the provided user ID. It retrieves the user, modifies the relevant fields, and saves the changes.


[verify_user.py](https://github.com/Bradkibs/EMS254/blob/main/auth/verify_user.py)

`generate_verification_token() Function`:

- This function generates a URL-safe verification token using the `secrets` module. The `token_urlsafe` method generates a random URL-safe text with the specified number of bytes (16 bytes in this case).

- The generated token is intended to be used as part of a verification URL sent to users for email confirmation.

`send_verification_email(user_email, verification_token) Function`:

- This function sends a verification email to the specified `user_email` with a verification token.

- It uses the `Mail` and `Message` classes from an email library (possibly Flask-Mail) to create and send an email.

- The subject of the email is set to 'Verification Email for EMS254', and the sender is retrieved from the environment variable `VERIFICATION_EMAIL`.

- The email body includes a verification URL constructed using `url_for`. The `url_for` function generates a fully qualified URL for a given endpoint (in this case, 'app_views.register') with the verification token as a parameter. The`_external=True` argument ensures that an absolute URL is generated.

- The email body also includes a message instructing the recipient to click the verification link to confirm their email address for EMS254. It also provides information on what to do if they didn't register for EMS254.

- The function attempts to send the email using `mail.send(msg)`. If the email is sent successfully, it returns a JSON response with a success message and status code 200. If there's an exception during the email sending process, it returns a JSON response with an error message and status code 502.

## `db`

[__init__.py](https://github.com/Bradkibs/EMS254/blob/main/db/__init__.py)

```
from db.storage import DB

storage = DB()
storage.reload()
```

[storage.py](https://github.com/Bradkibs/EMS254/blob/main/db/storage.py)

`class DB:`

- `class DB:` - Class that handles database connections and operations using SQLAlchemy in a Python application.

`Class Attributes`:

- `__engine`: This attribute represents an instance of the SQLAlchemy `create_engine` class, which is used for managing database connections. It is initialized in the class constructor.

- `__session`: This attribute represents a session object from SQLAlchemy's scoped_session. It is used for managing a unit of work and persists changes to the database.


`Constructor (__init__)`:

- Initializes the `DB` class. It takes values for PostgreSQL connection parameters (user, password, host, database name) from environment variables. It also checks the environment (`APP_ENV`) to determine if it's in a testing environment, in which case it drops all tables.

- Creates an instance of the SQLAlchemy `create_engine` class based on the provided connection parameters.

- Calls the `reload` method to create tables and initialize the session.

- If any errors occur during initialization, it raises a `SQLAlchemyError`.

## `models`

[accounts.py](https://github.com/Bradkibs/EMS254/blob/main/models/accounts.py)

SQLAlchemy model class named `Accounts`. This class represents a table in a relational database and is likely part of an ORM (Object-Relational Mapping) system.

`Table Configuration`:

- `__tablename__`: Specifies the name of the table in the database. In this case, it's set to 'accounts'.

`Columns`:

- `user_id`: A foreign key column that references the 'id' column in the 'users' table. It establishes a relationship with the 'User' model.
- `account_number`: A column representing the account number. It is set to be unique, indicating that each account should have a distinct account number.
- `Total_funds`: A column representing the total funds associated with the account.
- `incomming_funds`: A column representing incoming funds for the account.
- `outgoing_funds`: A column representing outgoing funds for the account.

`Relationship`:

- The `user` attribute establishes a bidirectional relationship between the 'User' and 'Accounts' models. It specifies that there is a relationship between the 'user_id' column in the 'Accounts' table and the 'id' column in the 'users' table. The relationship function is used to define this relationship.

`Constructor`:

- `__init__`: The constructor initializes the object, and it calls the constructor of the superclass `(super().__init__)` with any passed arguments and keyword arguments.

[basemodel.py](https://github.com/Bradkibs/EMS254/blob/main/models/basemodel.py)

`BaseModel`

- Model to be used as a base class for other models in an ORM-based system.

`Attributes`:

- `id`: A unique identifier for the model, typically a UUID stored as a string.
- `created_at`: A timestamp indicating the creation time of the model.
- `updated_at`: A timestamp indicating the last update time of the model.

`Constructor (__init__) Method`:

- The constructor initializes the object with either default values or values provided as arguments or keyword arguments.

- It sets the `id` to a new UUID if not provided. If provided, it converts the `created_at` and `updated_at` timestamps from strings to `datetime` objects.

- If `created_at` or `updated_at` is not provided, it sets them to the current UTC time.

`__str__ Method`:

- Provides a string representation of the object, displaying the class name, `id` , and the dictionary representation of the object.

`to_dict Method`:

- Returns a dictionary representation of the object, including class name, `id`, `created_at`, and `updated_at`. It excludes the `_sa_instance_state` attribute, which is typically used internally by SQLAlchemy.


[messages.py](https://github.com/Bradkibs/EMS254/blob/main/models/messages.py)

`class Messages(BaseModel, Base):`

`Class Definition`:

- The class inherits from both `BaseModel` and `Base`, indicating that it is an SQLAlchemy model and presumably extends some common functionality from the `BaseModel` class.

- The `__tablename__` attribute specifies the name of the table in the database. In this case, it's set to 'messages'.

`Attributes`:

- `content`: A column representing the content of the message. It is of type Text and cannot be null.

- `sender_id` and `receiver_id`: Columns representing foreign keys referencing the 'id' column in the 'users' table. These columns establish relationships with the 'User' model.

`Relationships`:

- `sender` and `receiver`: These are relationship attributes that define the sender and receiver relationships with the 'User' model. They use the relationship function from SQLAlchemy.

- `foreign_keys` parameter is used to specify which columns are used as foreign keys for the relationships.

- The `back_populates` parameter specifies the attribute on the 'User' model that represents the reverse relationship. It indicates that 'User' instances will have attributes named 'sent_messages' and 'received_messages' to access their respective messages.


[transactions.py](https://github.com/Bradkibs/EMS254/blob/main/models/transactions.py)

`class Transactions(BaseModel, Base):` - The transactions model we keep the senders and receivers in the same table and create a foreign key relationship to the users table ceate a virtual column for the sender and receiver in the users table.

`Class Definition`:

- The class inherits from both `BaseModel` and `Base`, indicating that it is an SQLAlchemy model and presumably extends some common functionality from the `BaseModel` class.

- The `__tablename__` attribute specifies the name of the table in the database. In this case, it's set to 'transactions'.

`Attributes`:

- `sender_id` and `receiver_id`: Columns representing foreign keys referencing the 'id' column in the 'users' table. These columns establish relationships with the 'User' model.

- `amount`: A column representing the amount of the transaction. It is of type `Float` and cannot be null.

- `status`: A column representing the status of the transaction. It is of type `String(255)` and has a default value of 'pending'.

`Relationships`:

- `sender` and `receiver`: These are relationship attributes that define the sender and receiver relationships with the 'User' model. They use the `relationship` function from SQLAlchemy.

- `foreign_keys` parameter is used to specify which columns are used as foreign keys for the relationships.

- The `back_populates` parameter specifies the attribute on the 'User' model that represents the reverse relationship. It indicates that 'User' instances will have attributes named 'sent_transactions' and 'received_transactions' to access their respective transactions.

[users.py](https://github.com/Bradkibs/EMS254/blob/main/models/users.py)

`class User(BaseModel, Base):`

`Class Definition`:

- The class inherits from both `BaseModel` and `Base`, indicating that it is an SQLAlchemy model and presumably extends some common functionality from the `BaseModel` class.

- The `__tablename__` attribute specifies the name of the table in the database. In this case, it's set to 'users'.

`Attributes`:

- `email, first_name, last_name, phone_number, location`: Columns representing user information. They are of type `String` and cannot be null. The location column has a default value of 'KENYA'.

- `password`: A column representing the user's password. It is of type `String` and cannot be null.

- `role`: A column representing the user's role. It uses `SQLAlchemyEnum` to define an enumeration for roles ('admin', 'user', 'customer_service'). The default role is 'user'.

- `is_active`: A column indicating whether the user is active or not. It is of type Boolean with a default value of `False`.

- `last_login`: A column representing the timestamp of the user's last login. It is of type `DateTime` and cannot be null.

`Relationships`:

- `accounts`: A relationship to the 'Accounts' table. It indicates that a user has an associated account. The uselist=False parameter suggests that it's a one-to-one relationship.

- `sent_transactions` and `received_transactions`: Relationships to the 'Transactions' table. They indicate the transactions where the user is the sender or receiver. These relationships use the `relationship` function and specify the foreign keys for each relationship.

- `sent_messages` and `received_messages`: Relationships to the 'Messages' table. They indicate the messages where the user is the sender or receiver. Similar to the transaction relationships, they use the `relationship` function and specify the foreign keys for each relationship.

`Constructor (__init__) Method`:

- The constructor initializes the object by calling the constructor of the superclass (`super().__init__`) with any passed arguments and keyword arguments.


### `Utils`

[Admin.py](https://github.com/Bradkibs/EMS254/blob/main/utils/Admin.py)

`Admin`

- This is utility / service class for administrative purposes in a system.

`Class Attributes`:

- `db`: This is a class attribute that represents an instance of the `DB` class. It is created when an instance of the `Admin` class is created.

`Methods`:

- `get_all_transactions`: This method retrieves all transactions from the database. It assumes that there is a `__db` attribute (which appears to be a typo and should be `db`) that is an instance of a class providing a method called `query` for querying the database. The `Transactions` class is the SQLAlchemy model for transactions, and `.all()` is used to fetch all records.

- `get_all_accounts`: Similar to `get_all_transactions`, this method retrieves all accounts from the database using the `Accounts` SQLAlchemy model.

- `get_all_users`: This method retrieves all users from the database using the `User` SQLAlchemy model.


[GetRelationships.py](https://github.com/Bradkibs/EMS254/blob/main/utils/GetRelationships.py)

`class GetRelationships:`

`GetRelationships`- Class that is responsible for retrieving related information from different tables in a database.

`Class Attributes`:

- `__db`: This is a class attribute that represents an instance of the `DB` class. It is created when an instance of the `GetRelationships` class is created.

`Methods`:

- `get_user_from_accounts(account_id)`: This method retrieves a user associated with a given account ID from the Accounts table. It assumes that there is an attribute named user in the Accounts model.

- `get_account_from_user(user_id)`: This method retrieves an account associated with a given user ID from the User table. It assumes that there is an attribute named accounts in the User model.

- `get_user_from_transactions(transaction_id)`: This method retrieves a user associated with a given transaction ID from the Transactions table. It assumes that there is an attribute named sender in the Transactions model.

- `get_user_from_account_number(account_number)`: This method retrieves a user associated with a given account number from the Accounts table. It assumes that there is an attribute named user in the Accounts model.


[TransactionServices.py](https://github.com/Bradkibs/EMS254/blob/main/utils/TransactionServices.py)

`class TransactionService:`

`Class Attributes`:

- `__db`: This is a class attribute that represents an instance of the DB class. It is created when an instance of the TransactionService class is created.

- The `reload()` method is called on the `__db` instance, indicating that it might be involved in managing database connections or configurations.

`Methods`:

`create_transaction(**kwargs)`: This method is responsible for creating a new transaction. It takes keyword arguments (kwargs) containing information about the transaction, such as `sender_id`, `receiver_id`, and `amount`. It creates a new instance of the `Transactions` model, sets its attributes with the provided information, adds it to the database, and then saves the changes.

`get_transaction(transaction_id)`: This method retrieves a specific transaction from the database based on the provided `transaction_id`.

`view_user_specific_transactions(user_id)`: This method retrieves all transactions where the provided `user_id` matches the `sender_id`. It retrieves a list of transactions from the database.

[messages.py](https://github.com/Bradkibs/EMS254/blob/main/utils/messages.py)

`MessagesService` class: This class contains methods for managing messages.

- `__db` attribute: This is an instance of a DB class

- `__db.reload():` This line of code is called during the initialization of the MessagesService class,
and it appears to reload the database. The exact behavior of this method depends on the implementation of the DB class.

- `create_message(self, **kwargs):` This method is used to create a new message. It takes keyword arguments (`content`, `sender_id`, `receiver_id`) to create a message object, adds it to the database, and then saves the changes to the database. It returns the created message.

- `get_message(self, message_id):` This method retrieves a message from the database based on its `message_id`.

- `get_specific_user_messages(self, user_id):` This method retrieves all messages associated with a specific user, identified by `user_id`, from the database.

- `delete_message(self, message_id):` This method deletes a message from the database based on its `message_id`.

- `delete_all_user_messages(self, user_id):` This method deletes all messages associated with a specific user, identified by `user_id`, from the database.


[transaction_logic.py](https://github.com/Bradkibs/EMS254/blob/main/utils/transaction_logic.py)

`TransactionService class:`

- `__db attribute:` This is an instance of a DB class, representing a database connection.

- `__db.reload():` This line of code is called during the initialization of the TransactionService class, and it reloads the database.

- `create_transaction(self, **kwargs):` This method is used to create a new transaction. It takes keyword arguments (`sender_id`, `receiver_id`, `amount`) to create a `Transactions` object, adds it to the database, and then saves the changes to the database. It returns the created transaction.

- `get_transaction(self, transaction_id):` This method retrieves a transaction from the database based on its `transaction_id`.

- `view_user_specific_transactions(self, user_id):` This method retrieves all transactions where the specified user is the sender, identified by `user_id`.


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

### `App`

[app.py](https://github.com/Bradkibs/EMS254/blob/main/app.py)

