# EMS254 Documentation

EMS254 is a mode of payment system that enables Third Party Payments using the Escrow Model and Technology.

This is an explanation on the backend structure of the Escrow System, EMS254.

### File Structure

`api/v1/views` - This is an api directory that has the routes/endpoints that are handling Registration, Login, User Profile, Logout

- `user_views.py`

`@app_views.route('/register', methods=['POST'])` - Flask route handling User Registration

`@app_views.route('/login', methods=['POST'])` - Flask route handling User Login

`@app_views.route('/profile', methods=['GET'])` - Flask Route redirecting a user to profile after Login

`@app_views.route('/logout', methods=['GET'])` - Flask Route handling Logout


`auth`

* `auth.py` - this file enables the use of JWT Authentication,  Containing a class that allowed token creation and cookies to be set

`def create_token(self, identity):` -

`def refresh_token(self, identity):` -

`def validate_jwt(self):` -

`def get_authenticated_user(self):` -

`def set_cookie(self, response, access_token):` -

`def unset_cookie(self, response, access_token):` -


`Authentication` is Done using JWT(JSON Web Token) - JWT stands for JSON Web Token. It is a compact,
URL-safe means of representing claims to be transferred between two parties.
The claims in a JWT are encoded as a JSON object that is used as the payload of a
JSON Web Signature (JWS) structure or as the plaintext of a JSON Web Encryption (JWE) structure,
enabling the claims to be digitally signed or integrity protected with a Message Authentication Code (MAC) and/or encrypted.

* `user_auth.py`

`def hash_password(self, password):` -

`def verify_password(self, candidate_password, hashed_password):` -

`def create_user(self, **kwargs):` -

`def get_user_by_email(self, email):` -

`def get_user_by_phone_number(self, phone_number):` -

`def get_user_by_id(self, id):` -

`def get_all_users(self):` -

`def delete_user(self, id):` -

`def update_user(self, id, email, password):` -


* `verify_user.py`


`User Verification`

`def generate_verification_token():`

`def send_verification_email(user_email, verification_token):`


`db`

* `__init__.py`

```
from db.storage import DB

storage = DB()
storage.reload()
```

* `storage.py`

`storage.py` - Python file that has CRUD (Create, Read, Update, Delete) Functionality for Database Operations

`def reload(self):` - Reload

`def add(self, obj):` - Add

`def save(self):` - Save

`def delete(self, obj=None):` - Delete

`def query(self, cls):` - Query

`def close(self):` - calls remove() method on the private session attr to close the session and stop using it

`def begin(self):` - calls begin() method on the private session attr to start a transaction

`def rollback(self):` - calls rollback() method on the private session attr to roll back a transaction


`models`

* `accounts.py`

```
from models.basemodel import BaseModel, Base
from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship

class Accounts(BaseModel, Base):
    __tablename__ = 'accounts'
    user_id = Column(String(255), ForeignKey('users.id'), nullable=False)
    account_number = Column(String(255), nullable=False, unique=True)
    Total_funds = Column(String(255), nullable=False)
    incomming_funds = Column(String(255), nullable=False)
    outgoing_funds = Column(String(255), nullable=False)

    user = relationship("User", back_populates="accounts")

    def __init__(self, *args, **kwargs):
        """Initialize the account"""
        super().__init__(*args, **kwargs)
```

* `basemodel.py`

```
#!usr/bin/python3
"""
Contains class BaseModel
"""
from sqlalchemy import Column, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
import uuid
from datetime import datetime

time = "%Y-%m-%dT%H:%M:%S.%f"

Base = declarative_base()


class BaseModel:
    """The BaseModel class from which future classes will be derived"""

    id = Column(String(60), primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

    def __init__(self, *args, **kwargs):
        """Initialization of the base model"""
        if kwargs:
            for key, value in kwargs.items():
                if key != "__class__":
                    setattr(self, key, value)
            if kwargs.get("created_at", None) and type(self.created_at) is str:
                self.created_at = datetime.strptime(kwargs["created_at"], time)
            else:
                self.created_at = datetime.utcnow()
            if kwargs.get("updated_at", None) and type(self.updated_at) is str:
                self.updated_at = datetime.strptime(kwargs["updated_at"], time)
            else:
                self.updated_at = datetime.utcnow()
            if kwargs.get("id", None) is None:
                self.id = str(uuid.uuid4())
        else:
            self.id = str(uuid.uuid4())
            self.created_at = datetime.utcnow()
            self.updated_at = self.created_at

    def __str__(self):
        """String representation of the BaseModel class"""
        return "[{:s}] ({:s}) {}".format(self.__class__.__name__, self.id,
                                         self.__dict__)
    def to_dict(self):
        """Return a dictionary containing all keys/values of __dict__"""
        my_dict = dict(self.__dict__)
        my_dict["__class__"] = self.__class__.__name__
        my_dict["created_at"] = self.created_at.isoformat()
        my_dict["updated_at"] = self.updated_at.isoformat()
        if "_sa_instance_state" in my_dict:
            del my_dict["_sa_instance_state"]
        return my_dict
```

* `messages.py` - Message Model that enables messages sent from sender and receiver


* `transactions.py` - The transactions model
    we keep the senders and receivers in the same table
    and create a foreign key relationship to the users table
    ceate a virtual column for the sender and receiver
    in the users table

* `users.py` - Model that Contains User Details and Facilitates Account Creation and Validation.

## Utils

* `messages.py` -  Messages class: This seems to be a class used to represent messages.

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

* `transaction_logic.py`

`TransactionService class:`

- `__db attribute:` This is an instance of a DB class, representing a database connection.

- `__db.reload():` This line of code is called during the initialization of the TransactionService class, and it reloads the database.

- `create_transaction(self, **kwargs):` This method is used to create a new transaction. It takes keyword arguments (`sender_id`, `receiver_id`, `amount`) to create a `Transactions` object, adds it to the database, and then saves the changes to the database. It returns the created transaction.

- `get_transaction(self, transaction_id):` This method retrieves a transaction from the database based on its `transaction_id`.

- `view_user_specific_transactions(self, user_id):` This method retrieves all transactions where the specified user is the sender, identified by `user_id`.











```
from models.transactions import Transactions
from db.storage import DB


class TransactionService:
    __db = DB()
    __db.reload()

    def create_transaction(self, **kwargs):
        """Create transaction"""
        sender_id = kwargs.get('sender_id')
        receiver_id = kwargs.get('receiver_id')
        amount = kwargs.get('amount')
        transaction = Transactions(sender_id=sender_id, receiver_id=receiver_id, amount=amount)
        self.__db.add(transaction)
        self.__db.save()
        return transaction

    def get_transaction(self, transaction_id):
        """Get transaction"""
        transaction = self.__db.query(Transactions).filter_by(id=transaction_id).first()
        return transaction

    def view_user_specific_transactions(self, user_id):
        """View user specific transactions"""
        transactions = self.__db.query(Transactions).filter_by(sender_id=user_id).all()
        return transactions
```

### User account file
* `user_account.py`

`AccountService class:`


- `__db attribute:` This is an instance of a DB class, representing a database connection.

- `__db.reload():` This line of code is called during the initialization of the `AccountService class`, and it reloads the database.

- `create_account_number(self):` This method generates a random account number.

- `create_account(self, **kwargs):` This method creates a new account by generating a unique account number and checking if it already exists in the database.
If it does, a new account number is generated. The method then creates an `Accounts` object, adds it to the database, and saves the changes.

- `get_account(self, account_number):` This method retrieves an account from the database based on its account number.

- `add_total_funds(self, account_number, amount):` This method adds funds to an account's total funds.

- `transact(self, amount, sender_id, receiver_id):` This method performs a transaction by subtracting the specified amount from the sender's account and adding it to the receiver's account. It also includes error checking, such as ensuring the amount is greater than 100, checking for sender and receiver IDs, verifying sufficient funds, and handling transactions using SQL transactions (`_db.begin()`, `_db.rollback()`, and `_db.save()`).


`app.py`

```
"""
Flask App sends and accept json api requests to the set frontend
"""
from datetime import timedelta

from flask import Flask, jsonify, make_response, request, redirect
from flask_cors import CORS, cross_origin
import os
from db import storage
from werkzeug.exceptions import HTTPException
from dotenv import load_dotenv
from flask_jwt_extended import JWTManager
from auth.auth import Authentication
from api.v1.views import app_views
from db.storage import DB
from celery import Celery

db = DB()
db.reload()

Auth = Authentication()


load_dotenv()


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
broker_url = os.getenv('CELERY_BROKER_URL')
celery = Celery(
    app.import_name,
    broker=broker_url
)

celery.conf.update(app.config, broker_connection_retry_on_startup=True)
# JWT config
jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)

# Mail server config
# app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
# app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
# app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
# app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
# app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS')
# app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL')
# app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')


app.url_map.strict_slashes = False

app.register_blueprint(app_views)

host = os.getenv("APP_HOST", "0.0.0.0")
port = os.getenv("APP_PORT", 5000)
environ = os.getenv("APP_ENV")

if environ == 'development':
    app.debug = True
else:
    app.debug = False

cors = CORS(app, origins="0.0.0.0")
cors = CORS(app, resources={r'/*': {'origins': host}})
cors = CORS(app, resources={r"/api/v1/*": {"origins": "*"}})


@app.route("/")
def home():
    access_token = Auth.create_token("Hello world")
    return jsonify({"access token": access_token}), 200

# @jwt.expired_token_loader
# def handle_expired_token_callback():
#     return redirect('/api/v1/views/login')
@app.before_request
def check_content_type():
    if request.method in ["POST", "PUT", "PATCH", "DELETE"] and request.headers["Content-Type"] != "application/json":
        return jsonify({"message": "Content-Type must be application/json"}), 400

@app.teardown_appcontext
def teardown_db(exception):
    """
    after each request, this method calls .close() (i.e. .remove()) on
    the current SQLAlchemy Session
    """
    storage.close()


@app.errorhandler(404)
def handle_404(exception):
    """
    handles 404 errors, in the event that global error handler fails
    """
    code = exception.__str__().split()[0]
    description = exception.description
    message = {'error': description}
    return make_response(jsonify(message), code)


@app.errorhandler(400)
def handle_404(exception):
    """
    handles 400 errors, in the event that global error handler fails
    """
    code = exception.__str__().split()[0]
    description = exception.description
    message = {'error': description}
    return make_response(jsonify(message), code)


@app.errorhandler(Exception)
def global_error_handler(err):
    """
        Global Route to handle All Error Status Codes
    """
    if isinstance(err, HTTPException):
        if type(err).__name__ == 'NotFound':
            err.description = "Not found"
        message = {'error': str(err)}
        code = err.code
    else:
        message = {'error': str(err)}
        code = 500
    return make_response(jsonify(message), code)


@app.after_request
def add_cors_headers(response):
    response.headers.extend({
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Headers': 'Content-Type, Cache-Control, X-Requested-With, Authorization',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, PUT, DELETE'
    })
    return response


def setup_global_errors():
    """
    This updates HTTPException Class with custom error function
    """
    for cls in HTTPException.__subclasses__():
        app.register_error_handler(cls, global_error_handler)


if __name__ == "__main__":
    """
    MAIN Flask App
    """
    # initializes global error handling
    setup_global_errors()
    # start Flask app
    app.run(host=host, port=port)
```