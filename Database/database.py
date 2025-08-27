from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS, cross_origin
import sqlite3
import requests
import bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
import base64
import os
from markupsafe import escape
from flask_wtf.csrf import CSRFProtect, generate_csrf
import re
from dotenv import load_dotenv
import bleach

# Load environment variables from .env
load_dotenv()

# Create the Flask app
app = Flask(__name__, static_folder='./Database', static_url_path='')

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
DATABASE = os.getenv('DATABASE', 'musesphere.db')
API_KEY = os.getenv('API_KEY', 'default_api_key')
API_BASE = os.getenv('API_BASE', 'https://api.harvardartmuseums.org/object')

# CSRF Protection
csrf = CSRFProtect(app)

ALLOW_ORIGINS = ['http://localhost:8080']

common_cors = dict(
    origins=ALLOW_ORIGINS,
    supports_credentials=True,
    methods=['POST', 'DELETE', 'OPTIONS'],
    allow_headers=['Content-Type', 'X-CSRFToken'],
)

# Enable CORS
CORS(
    app,
    resources={r"/register": {"origins": [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "null"
    ]}},
    supports_credentials=True
)

PROFILE_PIC_DIR = 'profile_pics'

if not os.path.exists(PROFILE_PIC_DIR):
    os.makedirs(PROFILE_PIC_DIR)


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        profile_pic TEXT,
        role TEXT DEFAULT 'user',
        address TEXT
    );

    CREATE TABLE IF NOT EXISTS artworks (
        id TEXT PRIMARY KEY,
        title TEXT,
        artist TEXT,
        image_url TEXT,
        culture TEXT,
        date TEXT
    );

    CREATE TABLE IF NOT EXISTS likes (
        user_id INTEGER,
        artwork_id TEXT,
        PRIMARY KEY (user_id, artwork_id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (artwork_id) REFERENCES artworks(id)
    );

    CREATE TABLE IF NOT EXISTS collections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT,
        description TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS collection_items (
        collection_id INTEGER,
        artwork_id TEXT,
        PRIMARY KEY (collection_id, artwork_id),
        FOREIGN KEY (collection_id) REFERENCES collections(id),
        FOREIGN KEY (artwork_id) REFERENCES artworks(id)
    );
    ''')
    conn.commit()
    conn.close()


def is_valid_username(username):
    """Validate username: 3-20 characters, alphanumeric with underscores."""
    return re.match(r'^[a-zA-Z0-9_]{3,20}$', username)

def is_valid_email(email):
    """Validate email format."""
    return re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email)


@app.route('/')
def home():
    return jsonify({'message': 'Welcome to the MuseSphere API!'})

# REMOVE LATER ONLY FOR VIEWING !!!!!!!!
@app.route('/view')
@csrf.exempt
@cross_origin(supports_credentials=True)
def view():
    con = sqlite3.connect(DATABASE)
    cur = con.cursor()
    cur.execute("SELECT * FROM users;")
    rows = cur.fetchall()
    con.close()
    return jsonify(rows)

@app.route('/register', methods=['POST'])
@csrf.exempt #disable CSRF for this route
@cross_origin(supports_credentials=True)
def register():
    data = request.json
    username = bleach.clean(data.get('username', '').strip())
    email = bleach.clean(data.get('email', '').strip())
    password = bleach.clean(data.get('password', '').strip())

    # Validate inputs
    if not is_valid_username(username):
        return jsonify({'success': False, 'error': 'Invalid username. Must be 3-20 characters long and can only contain letters, numbers, and underscores.'}), 400
    if not is_valid_email(email):
        return jsonify({'success': False, 'error': 'Invalid email address.'}), 400
    if not password:
        return jsonify({'success': False, 'error': 'Password is required.'}), 400

    # Hash the password
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert into database
    conn = get_db()
    try:
        conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                     (username, email, hashed_pw))
        conn.commit()
        return jsonify({'success': True, 'message': 'User registered'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'error': 'Username or email already exists'}), 400

@app.post("/login")
@csrf.exempt
@cross_origin(supports_credentials=True)
def login():
    data = request.get_json()
    identifier = bleach.clean(data["username"])  # Can be username OR email
    password = bleach.clean(data["password"]).encode('utf-8')  # Convert password to bytes

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM users WHERE username = ? OR email = ?",
        (identifier, identifier)
    )
    user = cur.fetchone()
    conn.close()

    # Fix: Remove `.encode('utf-8')` because `user["password"]` is already bytes
    if user and bcrypt.checkpw(password, user["password"]):  # Verify password
        session["user_id"] = user["id"]
        return jsonify(success=True, user_id=user["id"]), 200

    return jsonify(success=False, error="Invalid username or password"), 401


@app.route('/like', methods=['POST'])
@csrf.exempt #disable CSRF for this route
@cross_origin(supports_credentials=True)
def like_artwork():
    data = request.json
    user_id = bleach.clean(data['user_id'])
    artwork_id = bleach.clean(str(data['artwork_id']))

    # Fetch artwork from Harvard API if not already in DB
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM artworks WHERE id = ?', (artwork_id,))
    art = cur.fetchone()

    if not art:
        # Fetch from API
        resp = requests.get(f'{API_BASE}/{artwork_id}?apikey={API_KEY}')
        if resp.status_code != 200:
            return jsonify({'error': 'Invalid artwork ID'}), 400

        art_json = resp.json()
        conn.execute('INSERT INTO artworks (id, title, artist, image_url, culture, date) VALUES (?, ?, ?, ?, ?, ?)', (
            str(art_json.get('id')),
            art_json.get('title'),
            art_json.get('people')[0]['name'] if art_json.get('people') else 'Unknown',
            art_json.get('primaryimageurl'),
            art_json.get('culture'),
            art_json.get('dated')
        ))
        conn.commit()

    # Save the like
    try:
        conn.execute('INSERT INTO likes (user_id, artwork_id) VALUES (?, ?)', (user_id, artwork_id))
        conn.commit()
        return jsonify({'message': 'Artwork liked'}), 200
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Already liked'}), 400


#unlike
@app.route('/unlike', methods=['DELETE'])
@csrf.exempt #disable CSRF for this route
@cross_origin(supports_credentials=True)
def unlike_artwork():
    data = request.json
    user_id = bleach.clean(data['user_id'])
    artwork_id = bleach.clean(str(data['artwork_id']))

    conn = get_db()
    conn.execute('DELETE FROM likes WHERE user_id = ? AND artwork_id = ?', (user_id, artwork_id))
    conn.commit()
    return jsonify({'message': 'Artwork unliked'}), 200

@app.route('/collections/<int:user_id>', methods=['POST'])
@csrf.exempt
@cross_origin(supports_credentials=True)
def create_collection(user_id):
    data = request.json
    name = bleach.clean(data['name'])
    desc = bleach.clean(data.get('description', ''))

    conn = get_db()
    conn.execute('INSERT INTO collections (user_id, name, description) VALUES (?, ?, ?)',
                 (user_id, name, desc))
    conn.commit()
    return jsonify({'message': 'Collection created'}), 201


@app.route('/collections/<int:collection_id>/add', methods=['POST'])
@csrf.exempt
@cross_origin(supports_credentials=True)
def add_to_collection(collection_id):
    data = request.json
    artwork_id = bleach.clean(data['artwork_id'])
    conn = get_db()
    try:
        conn.execute('INSERT INTO collection_items (collection_id, artwork_id) VALUES (?, ?)',
                     (collection_id, artwork_id))
        conn.commit()
        return jsonify({'message': 'Artwork added to collection'}), 200
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Already in collection'}), 400


@app.route('/likes/<int:user_id>')
@csrf.exempt
@cross_origin(supports_credentials=True)
def get_liked_artworks(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT artworks.* FROM artworks
        JOIN likes ON artworks.id = likes.artwork_id
        WHERE likes.user_id = ?
    ''', (user_id,))
    liked = [dict(row) for row in cur.fetchall()]
    return jsonify(liked)



#uplaoding pfp to folder from user choosing one
@app.route('/uploadProfilePic', methods=['POST'])
@csrf.exempt
@cross_origin(supports_credentials=True)
def upload_profile_pic():
    data = request.json
    user_id = bleach.clean(data['user_id'])
    image_data = bleach.clean(data['image'])

    if ',' in image_data:
        image_data = image_data.split(',')[1]

    file_path = os.path.join(PROFILE_PIC_DIR, f'{user_id}.png')
    with open(file_path, 'wb') as f:
        f.write(base64.b64decode(image_data))

    conn = get_db()
    conn.execute('UPDATE users SET profile_pic = ? WHERE id = ?', (file_path, user_id))
    conn.commit()
    conn.close()

    return jsonify(success=True)

#takes pfp from folder
@app.route('/profilePic/<user_id>', methods=['GET'])
@csrf.exempt
@cross_origin(supports_credentials=True)
def get_profile_pic(user_id):
    pic_filename = f'{user_id}.png'
    abs_dir = os.path.abspath(PROFILE_PIC_DIR)
    file_path = os.path.join(abs_dir, pic_filename)

    if os.path.exists(file_path):
        return send_from_directory(abs_dir, pic_filename)
    else:
        return jsonify(success=False, error="No profile picture found"), 404


@app.route('/updateUser', methods=['PUT'])
@csrf.exempt
@cross_origin(supports_credentials=True)
def update_user():
    data = request.json
    user_id = bleach.clean(data.get('user_id'))
    new_username = bleach.clean(data.get('new_username', '').strip())
    new_password = bleach.clean(data.get('new_password', '').strip())

    if not user_id:
        return jsonify(success=False, error="User not authenticated"), 400

    conn = get_db()
    cur = conn.cursor()

    if new_username:
        if not is_valid_username(new_username):
            return jsonify(success=False, error="Invalid username. Must be 3-20 characters long and can only contain letters, numbers, and underscores."), 400
        try:
            cur.execute('UPDATE users SET username = ? WHERE id = ?', (new_username, user_id))
        except sqlite3.IntegrityError:
            return jsonify(success=False, error="Username already taken"), 400

    if new_password:
        hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        cur.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_pw, user_id))

    conn.commit()
    conn.close()

    return jsonify(success=True, message="User updated")


def is_admin():
    user_role = session.get('role')  # Assuming the user's role is stored in the session
    return user_role == 'admin'


@app.route('/admin/users', methods=['POST'])
@cross_origin(supports_credentials=True)
def add_user():
    if not is_admin():
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    data = request.json
    username = bleach.clean(data.get('username', '').strip())
    email = bleach.clean(data.get('email', '').strip())
    password = bleach.clean(data.get('password', '').strip())
    role = bleach.clean(data.get('role', 'user').strip())

    # Validate inputs
    if not is_valid_username(username):
        return jsonify({'success': False, 'error': 'Invalid username. Must be 3-20 characters long and can only contain letters, numbers, and underscores.'}), 400
    if not is_valid_email(email):
        return jsonify({'success': False, 'error': 'Invalid email address.'}), 400
    if not password:
        return jsonify({'success': False, 'error': 'Password is required.'}), 400

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
            (username, email, hashed_pw, role)
        )
        conn.commit()
        return jsonify({'success': True, 'message': 'User added successfully'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'error': 'Username or email already exists'}), 400


@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@cross_origin(supports_credentials=True)
def delete_user(user_id):
    # Check if the current user is an admin
    if not is_admin():
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    # Delete the user from the database
    conn = get_db()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    return jsonify({'success': True, 'message': 'User deleted successfully'}), 200


@app.route('/admin/users', methods=['GET'])
@cross_origin(supports_credentials=True)
def list_users():
    # Check if the current user is an admin
    if not is_admin():
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    # Fetch all users from the database
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT id, username, email, role, address FROM users')
    users = [dict(row) for row in cur.fetchall()]
    return jsonify({'success': True, 'users': users}), 200


@app.route('/admin/users/<int:user_id>', methods=['PUT'])
@cross_origin(supports_credentials=True)
def edit_user(user_id):
    # Check if the current user is an admin
    if not is_admin():
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    # Parse request data
    data = request.json
    username = bleach.clean(data.get('username', '').strip())
    email = bleach.clean(data.get('email', '').strip())
    role = bleach.clean(data.get('role', '').strip())
    address = bleach.clean(data.get('address', '').strip())

    # Update the user's details in the database
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        'UPDATE users SET username = ?, email = ?, role = ?, address = ? WHERE id = ?',
        (username, email, role, address, user_id)
    )
    conn.commit()
    return jsonify({'success': True, 'message': 'User updated successfully'}), 200


@app.route('/static/<path:filename>')
@cross_origin(supports_credentials=True)
def static_files(filename):
    return send_from_directory('static', filename)

@app.route('/<path:filename>')
@cross_origin(supports_credentials=True)
def public_files(filename):
    return send_from_directory('public', filename)


@app.route('/profile')
def profile():
    username = escape(request.args.get('username', ''))
    return f"Hello, {username}!"


@app.route('/csrf-token', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_csrf_token():
    token = generate_csrf()
    return jsonify({'csrf_token': token})


if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0", port=8000, debug=True)


