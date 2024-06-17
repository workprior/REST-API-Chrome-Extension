from flask import Flask, request, jsonify
# secutity
from config import Config
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, jwt_required
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect, generate_csrf
# from flask_cors import CORS
# database
from db_postgres.config import db 
from db_postgres.models import Users, Person, Comment
from flask_migrate import Migrate
from sqlalchemy.exc import SQLAlchemyError, DataError
from psycopg2.errors import StringDataRightTruncation


app = Flask(__name__)

app.config.from_object(Config)

db.init_app(app)
# init database in flask

# hashed password and dehashes password, used to regist and login
jwt = JWTManager(app)


bcrypt = Bcrypt(app)
# migrations
migrate = Migrate(app, db) 
# csrf toket
csrf = CSRFProtect(app) 

# CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST"], "allow_headers": ["Content-Type", "Authorization", "X-CSRFToken"]}})

# check this and rework
# CORS(app)


# Обробка помилок JWT
@jwt.unauthorized_loader
def custom_unauthorized_response(callback):
    return jsonify({'message': 'Missing authorization header'}), 401

@jwt.expired_token_loader
def custom_expired_token_response(jwt_header, jwt_payload):
    return jsonify({'message': 'Token has expired'}), 401

@jwt.invalid_token_loader
def custom_invalid_token_response(callback):
    return jsonify({'message': 'Invalid token'}), 422


@app.route('/register', methods=['POST'])
@csrf.exempt
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Missing required fields'}), 400

    user = Users.query.filter_by(username=username).first()
    if user:
        return jsonify({'message': 'Username already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = Users(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201



@app.route('/login', methods=['POST'])
@csrf.exempt
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Missing required fields'}), 400

    user = Users.query.filter_by(username=username).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid data'}), 400

    access_token = create_access_token(identity={'username': user.username})
    csrf_token = generate_csrf()
    return jsonify({'access_token': access_token, 'csrf_token': csrf_token}), 200

def create_url(id):
    first_part = 'https://www.dream-singles.com/'
    last_part = '.html'
    return first_part + id + last_part

@app.route('/addperson', methods=['POST'])
@csrf.exempt
@jwt_required()
def add_person_info():
    data = request.get_json()
    username = data.get('username')
    site_id = data.get('site_id')
    url = create_url(site_id)
    description = data.get('description')
    try:
        if not site_id or not description:
            return jsonify({'message': 'Missing required fields'}), 400

        person_data = Person(user_id=Users.query.filter_by(username=username).first().id, site_id=site_id, description=description, url=url)
        db.session.add(person_data)
        db.session.commit()
        return jsonify({'message': 'UserInfo added successfully'}), 201
    
    except DataError as e:
        db.session.rollback()
        if isinstance(e.orig, StringDataRightTruncation):
            return jsonify({'message': 'Data is too long for the field. Please provide a shorter value.'}), 400
        app.logger.error(f"DataError: {str(e)}")
        return jsonify({'message': 'Data is too long for the field. Please provide a shorter value.'}), 400

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'message': 'A database error occurred.'}), 500

    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

@app.route('/addcomment', methods=['POST']) 
@csrf.exempt
@jwt_required()
def add_comment_info():
    data = request.get_json()
    username = data.get('username')
    comment_text = data.get('content')
    site_id = data.get('site_id')
    try:
        if not comment_text:
            return jsonify({'message': 'Missing required fields'}), 400

        comment_data = Comment(
            user_id=Users.query.filter_by(username=username).first().id,
            comment_text=comment_text,
            person_id=Person.query.filter_by(site_id=site_id).first().id)

        db.session.add(comment_data)
        db.session.commit()
        return jsonify({'message': 'UserInfo added successfully'}), 201
    
    except DataError as e:
        db.session.rollback()
        if isinstance(e.orig, StringDataRightTruncation):
            return jsonify({'message': 'Data is too long for the field. Please provide a shorter value.'}), 400
        app.logger.error(f"DataError: {str(e)}")
        return jsonify({'message': 'Data is too long for the field. Please provide a shorter value.'}), 400

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'message': 'A database error occurred.'}), 500

    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

@app.route('/getperson/<int:id>', methods=['GET'])
@jwt_required()
def get_post_by_title(id):
    site_id = id
    if not site_id:
        return jsonify({'message': 'Missing title parameter'}), 400

    person = Person.query.filter_by(site_id=site_id).first()
    if not person:
        return jsonify({'message': 'Data not found'}), 404
    
    comments = Comment.query.filter_by(person_id=person.id).all()
    comments_list = [{
        'content': comment.comment_text,
        'date_create': comment.date_create,
        'username_comment': Users.query.filter_by(id=comment.user_id).first().username} for comment in comments]
    
    user = Users.query.filter_by(id=person.user_id).first()
    return jsonify({
        'site_id': person.site_id,
        'url': person.url,
        'description': person.description,
        'date_create': person.date_create,
        'username': user.username,
        'comments': comments_list
    }), 200