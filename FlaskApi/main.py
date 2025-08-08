from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import jwt
import uuid

# App setup
main= Flask(__name__)

# JWT config
SECRET_KEY = 'claSsework8000'
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

main.config['SECRET_KEY'] = SECRET_KEY

# In-memory databases
users_db = {}  # key = username
accounts = {}  # key = user_id

# Utils
def create_token(data, expires_delta=None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check for token in Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]  # Bearer <token>
            except IndexError:
                return jsonify({'message': 'Token format invalid'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            if username is None or username not in users_db:
                return jsonify({'message': 'Invalid token or user'}), 401
            current_user = users_db[username]
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired'}), 401
        except Exception:
            return jsonify({'message': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# 1. Signup
@main.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'detail': 'Username and password required'}), 400
    
    username = data['username']
    password = data['password']
    
    if username in users_db:
        return jsonify({'detail': 'Username already exists'}), 400
    
    user_id = str(uuid.uuid4())
    users_db[username] = {
        'username': username,
        'hashed_password': generate_password_hash(password),
        'id': user_id
    }
    accounts[user_id] = 0.0
    
    return jsonify({'message': 'User created', 'user_id': user_id}), 201

# 2. Login (get token)
@main.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'detail': 'Username and password required'}), 400
    
    username = data['username']
    password = data['password']
    
    user = users_db.get(username)
    if not user or not check_password_hash(user['hashed_password'], password):
        return jsonify({'detail': 'Invalid username or password'}), 401
    
    token = create_token(
        {'sub': user['username']}, 
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    return jsonify({
        'access_token': token,
        'token_type': 'bearer'
    }), 200

# 3. Deposit
@main.route('/deposit', methods=['POST'])
@token_required
def deposit(current_user):
    data = request.get_json()
    
    if not data or 'amount' not in data:
        return jsonify({'detail': 'Amount required'}), 400
    
    amount = data['amount']
    
    if amount <= 0:
        return jsonify({'detail': 'Amount must be positive'}), 400
    
    accounts[current_user['id']] += amount
    
    return jsonify({
        'message': 'Deposited',
        'balance': accounts[current_user['id']]
    }), 200

# 4. Withdraw
@main.route('/withdraw', methods=['POST'])
@token_required
def withdraw(current_user):
    data = request.get_json()
    
    if not data or 'amount' not in data:
        return jsonify({'detail': 'Amount required'}), 400
    
    amount = data['amount']
    
    if amount <= 0:
        return jsonify({'detail': 'Amount must be positive'}), 400
    
    if amount > accounts[current_user['id']]:
        return jsonify({'detail': 'Insufficient balance'}), 400
    
    accounts[current_user['id']] -= amount
    
    return jsonify({
        'message': 'Withdrawn',
        'balance': accounts[current_user['id']]
    }), 200

# 5. Balance
@main.route('/balance', methods=['GET'])
@token_required
def get_balance(current_user):
    return jsonify({
        'user_id': current_user['id'],
        'balance': accounts[current_user['id']]
    }), 200

# Error handlers
@main.errorhandler(404)
def not_found(error):
    return jsonify({'detail': 'Endpoint not found'}), 404

@main.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'detail': 'Method not allowed'}), 405

@main.errorhandler(500)
def internal_error(error):
    return jsonify({'detail': 'Internal server error'}), 500

if __name__ == '__main__':
    main.run(debug=True)