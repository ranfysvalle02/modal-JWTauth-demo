import os  
import jwt  
import datetime  
from flask import Flask, request, jsonify  
from flask_cors import CORS  
from werkzeug.security import generate_password_hash, check_password_hash  
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError  
  
app = Flask(__name__)  
app.secret_key = os.urandom(32)  
  
# Allow CORS for development purposes  
CORS(app)  
  
# Secret key for encoding JWTs  
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key')  
JWT_ALGORITHM = 'HS256'  
ACCESS_TOKEN_EXPIRE_MINUTES = 15  
REFRESH_TOKEN_EXPIRE_DAYS = 180  # Approximately 6 months  
  
users = {}  # In-memory user store  
refresh_tokens = {}  # In-memory refresh token store  
  
@app.route('/register', methods=['POST'])  
def register():  
    username = request.json.get('username')  
    password = request.json.get('password')  
  
    if not username or not password:  
        return jsonify({'status': 'failed', 'message': 'Username and password are required.'}), 400  
  
    if len(password) < 8:  
        return jsonify({'status': 'failed', 'message': 'Password must be at least 8 characters long.'}), 400  
  
    if username in users:  
        return jsonify({'status': 'failed', 'message': 'User already exists.'}), 400  
  
    # Hash the password for secure storage  
    password_hash = generate_password_hash(password)  
  
    users[username] = {  
        'password_hash': password_hash  
    }  
  
    return jsonify({'status': 'ok'}), 200  
  
@app.route('/authenticate', methods=['POST'])  
def authenticate():  
    username = request.json.get('username')  
    password = request.json.get('password')  
  
    if not username or not password:  
        return jsonify({'status': 'failed', 'message': 'Username and password are required.'}), 400  
  
    user = users.get(username)  
    if not user:  
        return jsonify({'status': 'failed', 'message': 'User not found.'}), 404  
  
    if not check_password_hash(user['password_hash'], password):  
        return jsonify({'status': 'failed', 'message': 'Invalid credentials.'}), 401  
  
    # Generate tokens  
    access_token = create_access_token(username)  
    refresh_token = create_refresh_token(username)  
  
    # Store refresh token  
    refresh_tokens[refresh_token] = username  
  
    return jsonify({  
        'status': 'ok',  
        'access_token': access_token,  
        'refresh_token': refresh_token  
    }), 200  
  
@app.route('/refresh', methods=['POST'])  
def refresh_token():  
    refresh_token = request.json.get('refresh_token')  
    username = refresh_tokens.get(refresh_token)  
  
    if not username:  
        return jsonify({'status': 'failed', 'message': 'Invalid refresh token.'}), 400  
  
    try:  
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])  
  
        # Generate new tokens  
        access_token = create_access_token(username)  
        new_refresh_token = create_refresh_token(username)  
  
        # Update refresh tokens  
        del refresh_tokens[refresh_token]  
        refresh_tokens[new_refresh_token] = username  
  
        return jsonify({  
            'status': 'ok',  
            'access_token': access_token,  
            'refresh_token': new_refresh_token  
        }), 200  
  
    except ExpiredSignatureError:  
        return jsonify({'status': 'failed', 'message': 'Refresh token expired.'}), 400  
    except InvalidTokenError:  
        return jsonify({'status': 'failed', 'message': 'Invalid refresh token.'}), 400  
  
@app.route('/protected', methods=['GET'])  
def protected():  
    auth_header = request.headers.get('Authorization', None)  
    if not auth_header:  
        return jsonify({'status': 'failed', 'message': 'Missing Authorization header.'}), 401  
  
    try:  
        token_type, token = auth_header.split()  
        if token_type != 'Bearer':  
            raise ValueError('Invalid token type.')  
  
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])  
        username = payload.get('sub')  
  
        return jsonify({'status': 'ok', 'message': f'Hello, {username}!'}), 200  
    except ExpiredSignatureError:  
        return jsonify({'status': 'failed', 'message': 'Access token expired.'}), 401  
    except Exception as e:  
        return jsonify({'status': 'failed', 'message': str(e)}), 401  
  
def create_access_token(username):  
    payload = {  
        'sub': username,  
        'iat': datetime.datetime.utcnow(),  
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  
    }  
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)  
    return token  
  
def create_refresh_token(username):  
    payload = {  
        'sub': username,  
        'iat': datetime.datetime.utcnow(),  
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)  
    }  
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)  
    return token  
  
if __name__ == '__main__':  
    app.run(debug=True)  