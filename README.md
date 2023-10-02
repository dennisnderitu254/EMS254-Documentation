# EMS 254 Docs

EMS254 is a mode of payment system that enables Third Party Payments using the Escrow Model and Technology.

This is an explanation on the backend structure of the Escrow System, EMS254.


File Structure

`api/v1/views` - This is an api directory that has the routes/endpoints that are handling Registration, Login, User Profile, Logout

- `user_views.py`

```
from flask import jsonify, request
from auth.auth import Authentication
from auth.user_auth import UserAuth
from datetime import datetime
from api.v1.views import app_views
#from auth.verify_user import generate_verification_token, send_verification_email
from flask_jwt_extended import jwt_required
from utils.user_account import AccountService

user_auth = UserAuth()
user_authenticator = Authentication()
account_service = AccountService()

@app_views.route('/register', methods=['POST'])
def register_user():
    """
    Register a new user
    """
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    phone_number = data.get('phone_number')
    location = data.get('location')

    if not email:
        return jsonify({"message": "email is required"}), 400
    if not password:
        return jsonify({"message": "password is required"}), 400
    if not first_name:
        return jsonify({"message": "first_name is required"}), 400
    if not last_name:
        return jsonify({"message": "last_name is required"}), 400
    if not phone_number:
        return jsonify({"message": "phone_number is required"}), 400
    if not location:
        return jsonify({"message": "location is required"}), 400
    is_active = False
    last_login = datetime.utcnow()
    last_login_str = last_login.strftime("%Y-%m-%d %H:%M:%S")
    user = user_auth.get_user_by_email(email)
    if user:
        return jsonify({"message": "user already exists"}), 409
    else:
        usr = user_auth.create_user(email=email, password=password, first_name=first_name, last_name=last_name, phone_number=phone_number, location=location, is_active=is_active, last_login=last_login_str)
        account = account_service.create_account(Total_funds=0, incomming_funds=0, outgoing_funds=0, user_id=usr.id)
        #verification_token = generate_verification_token()
        #mail_response = send_verification_email(user_email=email, verification_token=verification_token)
        account_deets = { 'account_number': account.account_number, 'Total_funds': account.Total_funds, 'incomming_funds': account.incomming_funds, 'outgoing_funds': account.outgoing_funds, 'user_id': account.user_id }
        return jsonify({"message": "user created successfully", "user_id": str(usr.id), "account_message": "account created with the following credentials", 'account_details': account_deets}), 201


#@app_views.route('/verify_email/<string: token>', methods=['GET'])
#def verify_email(token):

@app_views.route('/login', methods=['POST'])
def login_user():
    """
    Login a user
    """
    data = request.get_json()
    email = data.get('email')
    phone_number = data.get('phone_number')
    password = data.get('password')

    if not email and not phone_number:
        return jsonify({"message": "email or phone number is required"}), 400
    if not password:
        return jsonify({"message": "password is required"}), 400
    if email:
        user = user_auth.get_user_by_email(email)
        if not user:
            return jsonify({"message": "user not found"}), 404
        if not user_auth.verify_password(password, user.password):
            return jsonify({"message": "invalid password"}), 400
        else:
            access_token = user_authenticator.create_token(user.id)
            response = jsonify({"message": "Logged in successfully!", 'status': 200})
            user_authenticator.set_cookie(response, access_token)
            return response
    if phone_number:
        user = user_auth.get_user_by_email(phone_number)
        if not user:
            return jsonify({"message": "user not found"}), 404
        if not user_auth.verify_password(password, user.password):
            return jsonify({"message": "invalid password"}), 400
        else:
            access_token = user_authenticator.create_token(user.id)
            response = jsonify({"message": "Logged in successfully!", "status": 200})
            user_authenticator.set_cookie(response, access_token)
            return response


@app_views.route('/profile', methods=['GET'])
@jwt_required()
def get_user():
    """
    Get a user
    """
    user_id = user_authenticator.get_authenticated_user()
    user = user_auth.get_user_by_id(user_id)
    if not user:
        return jsonify({"message": "user not found"}), 404
    user_data = {
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "phone_number": user.phone_number,
        "location": user.location,
        "role": user.role,
        "is_active": user.is_active,
        "last_login": user.last_login

    }
    return jsonify(user_data), 200


@app_views.route('/logout', methods=['GET'])
def logout():
    pass
```

`@app_views.route('/register', methods=['POST'])` - Flask route handling User Registration

`@app_views.route('/login', methods=['POST'])` - Flask route handling User Login

`@app_views.route('/profile', methods=['GET'])` - Flask Route redirecting a user to profile after Login

`@app_views.route('/logout', methods=['GET'])` - Flask Route handling Logout



`auth`

* `auth.py`

```
from flask_jwt_extended import create_access_token, get_jwt_identity, unset_jwt_cookies, \
    set_access_cookies, verify_jwt_in_request


class Authentication:

    __token = None

    def create_token(self, identity):
        self.__token = create_access_token(identity=identity)
        return self.__token

    def refresh_token(self, identity):
        self.create_token(identity)

    def validate_jwt(self):
        try:
            verify_jwt_in_request()
        except Exception as e:
            return False
        return True
    def get_authenticated_user(self):
        if self.validate_jwt():
            return get_jwt_identity()
        return None

    def set_cookie(self, response, access_token):
        set_access_cookies(response, access_token)

    def unset_cookie(self, response, access_token):
        unset_jwt_cookies(response, access_token)
```





* `user_auth.py`

```
from models.users import User
#from models.accounts import Accounts
from models.messages import Messages
from models.transactions import Transactions
from uuid import uuid4
from db.storage import DB
from bcrypt import hashpw, gensalt, checkpw

class UserAuth:
    _db = DB()
    _db.reload()

    def hash_password(self, password):
        password_bytes = password.encode('utf-8')
        salt = gensalt()
        hashed_password = hashpw(password_bytes, salt)
        return hashed_password.decode('utf-8')

    def verify_password(self, candidate_password, hashed_password):
        candidate_password_bytes = candidate_password.encode('utf-8')
        hashed_password_bytes = hashed_password.encode('utf-8')
        return checkpw(candidate_password_bytes, hashed_password_bytes)

    def create_user(self, **kwargs):
        email = kwargs.get('email')
        password = kwargs.get('password')
        first_name = kwargs.get('first_name')
        last_name = kwargs.get('last_name')
        phone_number = kwargs.get('phone_number')
        location = kwargs.get('location')
        role = kwargs.get('is_superuser')
        is_active = kwargs.get('is_active')
        login_time = kwargs.get('last_login')
        password = self.hash_password(password)
        user = User(email=email, password=password, first_name=first_name, last_name=last_name, phone_number=phone_number, location=location, role=role, is_active=is_active, last_login=login_time)
        self._db.add(user)
        self._db.save()
        return user

    def get_user_by_email(self, email):
        try:
            return self._db.query(User).filter_by(email=email).first()
        except Exception as e:
            return None
    def get_user_by_phone_number(self, phone_number):
        try:
            return self._db.query(User).filter_by(phone_number=phone_number).first()
        except Exception as e:
            return None
    def get_user_by_id(self, id):
        try:
            return self._db.query(User).filter_by(id=id).first()
        except Exception as e:
            return None

    def get_all_users(self):
        return self._db.query(User).all()

    def delete_user(self, id):
        user = self.get_user_by_id(id)
        self._db.delete(user)
        self._db.save()
        return True

    def update_user(self, id, email, password):
        try:
            user = self.get_user_by_id(id)
            if user:
                if email:
                    user.email = email
                if password:
                    user.password = self.hash_password(password)
                self._db.save()
                return user
            return None
        except Exception as e:
            return None
```

* `verify_user.py`

```
import secrets
from flask import url_for, jsonify
from flask_mail import Mail, Message
from os import getenv

def generate_verification_token():
    return secrets.token_urlsafe(16)


def send_verification_email(user_email, verification_token):
    subject = 'Verification Email for EMS254'
    mail = getenv('VERIFICATION_EMAIL')
    msg = Message(subject, sender=mail, recipients=[user_email])
    mail = Mail()
    verification_url = url_for('app_views.register', token=verification_token, _external=True)

    # Updated email body with a clear message.
    msg.body = f"Hello,\n\nPlease click the following link to verify your email address for EMS254:\n{verification_url}\n\nIf you didn't register for EMS254, you can safely ignore this email.\n\nBest regards,\nThe EMS254 Team"
    try:
        mail.send(msg)
        return jsonify({"Message": "Mail sent successfully", "status": 200})
    except Exception as e:
        return jsonify({"Mail sending Error": str(e), "status": 502})
```

`db`

* `__init__.py`

```
from db.storage import DB

storage = DB()
storage.reload()
```

* `storage.py`

```
from sqlalchemy.orm import sessionmaker
from models.basemodel import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from os import getenv
from dotenv import load_dotenv


load_dotenv()


class DB:
    """
    DB class
    """

    __engine = None
    __session = None

    def __init__(self):
        """
        Constructor
        """

        user = getenv('PG_USER')
        password = getenv('PG_PWD')
        host = getenv('PG_HOST')
        db_name = getenv('PG_DB')
        env = getenv('APP_ENV')
        pg_url = getenv('PG_URL')
        try:
            self.__engine = create_engine(f'postgresql://{user}:{password}@{host}/{db_name}')
            # self.__engine = create_engine(pg_url)
            #self.reload()

            if env == 'test':
                Base.metadata.drop_all(self.__engine)
        except SQLAlchemyError as e:
            raise e


    def reload(self):
        """
        Reload
        """

        Base.metadata.create_all(self.__engine)
        session_maker = sessionmaker(bind=self.__engine, expire_on_commit=False)
        self.__session = scoped_session(session_maker)



    def add(self, obj):
        """
        Add
        """

        self.__session.add(obj)

    def save(self):
        """
        Save
        """

        self.__session.commit()

    def delete(self, obj=None):
        """
        Delete
        """

        if obj:
            self.__session.delete(obj)

    def query(self, cls):
        """
        Query
        """

        return self.__session.query(cls)

    def close(self):
        """calls remove() method on the private session attr to close the session and stop using it"""
        self.__session.remove()

    def begin(self):
        """calls begin() method on the private session attr to start a transaction"""
        self.__session.begin()

    def rollback(self):
        """calls rollback() method on the private session attr to roll back a transaction"""
        self.__session.rollback()
```


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

* `messages.py`

```
from models.basemodel import BaseModel, Base
from sqlalchemy import Column, String, ForeignKey, Text
from sqlalchemy.orm import relationship

class Messages(BaseModel, Base):
    """ The messages model"""
    __tablename__ = 'messages'

    content = Column(Text, nullable=False)

    # Define the foreign key relationship to the sender user
    sender_id = Column(String(255), ForeignKey('users.id'), nullable=False)
    receiver_id = Column(String(255), ForeignKey('users.id'), nullable=False)

    # Define the sender and receiver relationships
    sender = relationship('User', foreign_keys=[sender_id], backref='sent_message')
    receiver = relationship('User', foreign_keys=[receiver_id], backref='received_message')
```

* `transactions.py`

```
from models.basemodel import BaseModel, Base
from sqlalchemy import Column, String, ForeignKey, Float
from sqlalchemy.orm import relationship

class Transactions(BaseModel, Base):

    """ The transactions model
    we keep the senders and receivers in the same table
    and create a foreign key relationship to the users table
    ceate a virtual column for the sender and receiver
    in the users table
    """
    __tablename__ = 'transactions'

    # Define the foreign key relationship to the sender user
    sender_id = Column(String(255), ForeignKey('users.id'), nullable=False)

    # Define the foreign key relationship to the receiver user
    receiver_id = Column(String(255), ForeignKey('users.id'), nullable=False)

    # Amount of the transaction
    amount = Column(Float, nullable=False)

    # Define the sender and receiver relationships
    sender = relationship('User', foreign_keys=[sender_id], backref='sent_transaction')
    receiver = relationship('User', foreign_keys=[receiver_id], backref='received_transaction')
```



* `users.py`

```
from models.basemodel import BaseModel, Base
from sqlalchemy import Column, String, DateTime, Boolean, Enum as SQLAlchemyEnum
from sqlalchemy.orm import relationship

class User(BaseModel, Base):
    __tablename__ = 'users'
    email = Column(String(255), nullable=False, unique=True)
    first_name = Column(String(255), nullable=False)
    last_name = Column(String(255), nullable=False)
    phone_number = Column(String(20), nullable=False)
    location = Column(String(255), nullable=False, default='KENYA')
    password = Column(String(255), nullable=False)
    role = Column(SQLAlchemyEnum('admin', 'user', 'customer_service', name='user_role_enum'), default='user', nullable=False)
    is_active = Column(Boolean, default=False)
    last_login = Column(DateTime, nullable=False)

    # Define the relationship to the accounts table
    accounts = relationship("Accounts", uselist=False, back_populates="user")

    # Define the relationship to the transactions table
    sent_transactions = relationship('Transactions', foreign_keys='Transactions.sender_id', backref='sender_user', lazy=True)
    received_transactions = relationship('Transactions', foreign_keys='Transactions.receiver_id', backref='receiver_user', lazy=True)

    # Define the relationship to the messages table
    sent_messages = relationship('Messages', foreign_keys='Messages.sender_id', backref='sender_user_messages', lazy=True)
    received_messages = relationship('Messages', foreign_keys='Messages.receiver_id', backref='receiver_user_messages', lazy=True)

    def __init__(self, *args, **kwargs):
        """Initialize the user"""
        super().__init__(*args, **kwargs)
```


`utils`

* `messages.py`

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