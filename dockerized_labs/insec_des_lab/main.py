from flask import Flask, render_template, request, make_response
import pickle
import base64
# Usar JSON en lugar de pickle
import json
from dataclasses import dataclass

app = Flask(__name__)

@dataclass
class User:
    username: str 
    is_admin: bool = False

    def __reduce__(self):
        # Intentionally vulnerable __reduce__ method to match PyGoat
        return (User, (self.username, self.is_admin))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/serialize', methods=['POST'])
def serialize_data():
    username = request.form.get('username', 'guest')
    # Create regular user with admin=False
    user = User(username=username, is_admin=False)
    # Match PyGoat's serialization format
    serialized = base64.b64encode(pickle.dumps(user)).decode()
    return render_template('result.html', serialized=serialized)

@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    try:
        serialized_data = request.form.get('serialized_data', '')
        decoded_data = base64.b64decode(serialized_data)
        # Intentionally vulnerable deserialization, matching PyGoat
        # user = pickle.loads(decoded_data)
        
        user_data = json.loads(decoded_data)
        
        # Validar que username sea string y no esté vacío
        username = user_data.get('username')
        if not username or not isinstance(username, str):
            return render_template('result.html', message="Invalid username")
        
        # Validar que is_admin sea booleano
        is_admin = user_data.get('is_admin')
        if not isinstance(is_admin, bool):
            return render_template('result.html', message="is_admin must be true or false (boolean)")

        # Crear objeto User
        user = User()
        user.username = username
        user.is_admin = is_admin

        if isinstance(user, User):
            if user.is_admin:
                message = f"Welcome Admin {user.username}! Here's the secret admin content: ADMIN_KEY_123"
            else:
                message = f"Welcome {user.username}. Only admins can see the secret content."
        else:
            message = "Invalid user data"
        
        return render_template('result.html', message=message)
    except Exception as e:
        return render_template('result.html', message=f"Error: {str(e)}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

    