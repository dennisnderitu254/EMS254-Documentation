# EMS254 Documentation

EMS254 is a mode of payment system that enables Third Party Payments using the Escrow Model and Technology.

This is an explanation on the backend structure of the Escrow System, EMS254.


### File Structure

`EMS254/tree/main/api/v1/views/user` - This is an path that has the routes/endpoints that are handling Registration, Login, User Profile, Logout

[user_views.py](https://github.com/Bradkibs/EMS254/blob/main/api/v1/views/user/users_views.py)

`@app_views.route('/register', methods=['POST'])`

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


`@app_views.route('/login', methods=['POST'])`


### auth

[auth.py](https://github.com/Bradkibs/EMS254/blob/main/auth/auth.py) - This file enables the use of JWT Authentication,  Containing a class that allowed token creation and cookies to be set


`Authentication` is Done using JWT(JSON Web Token) - JWT stands for JSON Web Token. It is a compact,
URL-safe means of representing claims to be transferred between two parties.
The claims in a JWT are encoded as a JSON object that is used as the payload of a
JSON Web Signature (JWS) structure or as the plaintext of a JSON Web Encryption (JWE) structure,
enabling the claims to be digitally signed or integrity protected with a Message Authentication Code (MAC) and/or encrypted.

[user_auth.py](https://github.com/Bradkibs/EMS254/blob/main/auth/user_auth.py)




[verify_user.py](https://github.com/Bradkibs/EMS254/blob/main/auth/verify_user.py)



### db

[__init__.py](https://github.com/Bradkibs/EMS254/blob/main/db/__init__.py)

```
from db.storage import DB

storage = DB()
storage.reload()
```

[storage.py](https://github.com/Bradkibs/EMS254/blob/main/db/storage.py)


### models

[accounts.py](https://github.com/Bradkibs/EMS254/blob/main/models/accounts.py)



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

