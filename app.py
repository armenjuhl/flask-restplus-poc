from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = ('sqlite:////media/sf_VMSharedFolder/FaskRestPlus/todo.db')

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(80))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        time = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        token = jwt.encode({'public_id': user.public_id, 'exp': time}, app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})

    users = User.query.all()

    user_list = []
    output = {}

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        user_list.append(user_data)
        print('\n\n1', user_data)
    print('\n\n2', user_list)

    output['users'] = user_list
    print('\n\n3', output['users'])
    print('\n\n4', output)

    return jsonify({'payload': output})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})

    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    if User.query.filter_by(name=data['name']).first():
        return jsonify({'message': 'username already exists!'})
    else:
        new_user = User(public_id=str(uuid.uuid4())[:8], name=data['name'], password=hashed_password, admin=False)
        db.session.add(new_user)
        db.session.commit()

    return jsonify({'message': 'New user created!'})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    user = {}
    user['user'] = user_data

    return jsonify({'payload': user})

@app.route('/user/promote/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    if user.admin == True:
        message = 'The user is already an admin'
    elif user.admin == False:
        message = 'The user has been promoted'

    user.admin = True
    db.session.commit()

    output = {}
    output['message'] = message
    return jsonify({'payload': output})

@app.route('/user/demote/<public_id>', methods=['PUT'])
@token_required
def demote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    if user.admin == False:
        message = 'The user is not an admin'
    elif user.admin == True:
        message = 'The user has been demoted'

    user.admin = False
    db.session.commit()

    output = {}
    output['message'] = message
    return jsonify({'payload': output})

@token_required
@app.route('/user/<public_id>', methods=['DELETE'])
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})

    message = {}
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    message['message'] = 'The user has been deleted'
    return jsonify({'payload': message})

# /////////////////////////////////////////////////////////////////////////////
# TODO SECTION
# /////////////////////////////////////////////////////////////////////////////

@app.route('/todo', methods=['GET'])
@token_required
def get_all_todos(current_user):

    todo_list = []
    for task in Todo.query.all():
        task_item = dict()
        task_item['id'] = task.id
        task_item['text'] = task.text
        task_item['complete'] = task.complete
        task_item['user_id'] = task.user_id
        todo_list.append(task_item)

    todos = {'todos': todo_list}

    return jsonify({'payload': todos})


@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message': 'No todo found!'})

    todo_data = {}
    todo_data['id'] = todo.id
    todo_data['text'] = todo.text
    todo_data['complete'] = todo.complete
    output = {'todo': todo_data}

    return jsonify({'payload': output})


@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()

    new_todo = Todo(text=data['text'], complete=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()

    return jsonify({'message': 'Todo created!'})

@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message': 'No todo found!'})

    if todo.complete == True:
        return jsonify({'message': 'That task is already completed!'})
    else:
        todo.complete = True
        db.session.commit()


    return jsonify({'message': 'Todo item has been completed'})

@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message': 'No todo found!'})

    db.session.delete(todo)
    db.session.commit()

    return jsonify({"message": 'Todo item deleted'})


if __name__ == '__main__':
    app.run(debug=True)

