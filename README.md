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

* `utils`

* `messages.py` -

```
from models.messages import Messages
from db.storage import DB

messages = Messages()

class MessagesService:
    __db = DB()
    __db.reload()

    def create_message(self, **kwargs):
        """Create message"""
        content = kwargs.get('content')
        sender_id = kwargs.get('sender_id')
        receiver_id = kwargs.get('receiver_id')
        message = Messages(content=content, sender_id=sender_id, receiver_id=receiver_id)
        self.__db.add(message)
        self.__db.save()
        return message

    def get_message(self, message_id):
        """Get message"""
        message = self.__db.query(Messages).filter_by(id=message_id).first()
        return message

    def get_specific_user_messages(self, user_id):
        """Get specific user messages"""
        messages = self.__db.query(Messages).filter_by(receiver_id=user_id).all()
        return messages

    def delete_message(self, message_id):
        """Delete message"""
        message = self.__db.query(Messages).filter_by(id=message_id).first()
        self.__db.delete(message)
        self.__db.save()
        return message

    def delete_all_user_messages(self, user_id):
        """Delete all user messages"""
        messages = self.__db.query(Messages).filter_by(receiver_id=user_id).all()
        for message in messages:
            self.__db.delete(message)
            self.__db.save()
        return messages
```


* `transaction_logic.py`

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


* `user_account.py`

```
from models.accounts import Accounts
from db.storage import DB
import random
from flask import jsonify
from sqlalchemy.exc import SQLAlchemyError


class AccountService:
    __db = DB()
    __db.reload()


    def create_account_number(self):
        """Create account number"""
        account_number = str(random.randint(10*9, 10**10-1))
        return account_number

    def create_account(self, **kwargs):
        """Create account"""
        account_number = self.create_account_number()
        # check if account number exists
        account_exists = self.__db.query(Accounts).filter_by(account_number=account_number).first()
        if account_exists:
            while account_exists:
                account_number = self.create_account_number()
        Total_funds = kwargs.get('Total_funds')
        incomming_funds = kwargs.get('incomming_funds')
        outgoing_funds = kwargs.get('outgoing_funds')
        user_id = kwargs.get('user_id')
        account = Accounts(account_number=account_number, Total_funds=Total_funds, incomming_funds=incomming_funds, outgoing_funds=outgoing_funds, user_id=user_id)
        self.__db.add(account)
        self.__db.save()
        return account

    def get_account(self, account_number):
        """Get account"""
        account = self.__db.query(Accounts).filter_by(account_number=account_number).first()
        return account

    def add_total_funds(self, account_number, amount):
        """Add total funds"""
        account = self.__db.query(Accounts).filter_by(account_number=account_number).first()
        account.Total_funds += amount
        self.__db.save()
        return account

    def transact(self, amount, sender_id, receiver_id):
        """ creating a sql transaction"""
        if not amount and amount < 100:
            return jsonify({"message": "Amount must be greater than 100"}), 400
        if not sender_id:
            return jsonify({"message": "Sender id is required"}), 400
        if not receiver_id:
            return jsonify({"message": "Receiver id is required"}), 400
        sender_account = self.__db.query(Accounts).filter_by(user_id=sender_id).first()
        receiver_account = self.__db.query(Accounts).filter_by(user_id=receiver_id).first()

        if sender_account and receiver_account:
            if sender_account.Total_funds < amount:
                return jsonify({"message": "Insufficient funds"}), 400
            try:
                self._db.begin()
                sender_account.Total_funds -= amount
                sender_account.outgoing_funds += amount
                receiver_account.incoming_funds += amount
                self._db.save()

            except SQLAlchemyError as e:
                self._db.rollback()
                return jsonify({"message": "Transaction failed"}), 400
        else:
            return jsonify({"message": "The sender_account or receiver account does not exist"}), 400

        return jsonify({"message": "Transaction successful"}), 200
```

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