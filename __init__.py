import os
import functools
from flask import Flask, request, session, g, abort, jsonify
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import create_access_token, current_user, jwt_required, JWTManager
from .models import db, User, Note

def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY', default='dev')
    )
    if test_config is None:
        app.config.from_pyfile('config.py', silent=True)
    else:
        app.config.from_mapping(test_config)
    jwt = JWTManager(app)
    db.init_app(app)

    migrate = Migrate(app, db)    
    CORS(app)

    @app.after_request
    def after_request(response):
        # origin = request.headers.get('Origin')
        response.headers.add('Access-Control-Allow-Headers',
        'Content-Type,Authorization,authorization,true')
        response.headers.add('Access-Control-Allow-Methods',
        'GET, PATCH, POST, DELETE, OPTIONS'),
        response.headers.add('Access-Control-Allow-Domain', '*')
        return response
    
    @jwt.user_identity_loader
    def user_identity_lookup(user):
        return user.id
    
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data["sub"]
        return User.query.filter_by(id=identity).one_or_none()

    # def require_login(func):
    #     @functools.wraps(func)
    #     def auth_wrapper(**kwargs):
    #         if g.user:
    #             return func(**kwargs)
    #         else:
    #             abort(401)
    #     return auth_wrapper


    # @app.before_request
    # def load_user():
    #     user_id = session.get('user_id')
    #     if user_id:
    #         g.user = User.query.get(user_id)
    #     else:
    #         g.user = None
    

    @app.route('/sign_up', methods=['POST'])
    def sign_up():
        body = request.get_json()
        username = body['username']
        password = body['password']
        error = None
        if not username:
            # error = 'Username is required.'
            abort(400)
        elif not password:
            # error = 'Password is required.'
            abort(400)
        try:
            
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                abort(400)
                # error = 'Username is already taken.'
        except:
            abort(422)
        try:
            # user = User(username=username, password=generate_password_hash(password))
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            # login_user(user) # flask-login feature
            return jsonify({
                'success': True,
                'user_added': {'username': username}
            })
        except Exception as error:
            print(f'Exception: {error}')
            abort(422)

    @app.route('/log_in', methods=['POST'])
    def log_in():
        body = request.get_json()
        username = body.get('username')
        password = body.get('password')
        error = None
        if not username:
            # error = 'Username is required.'
            abort(400)
        elif not password:
            # error = 'Password is required.'
            abort(400)
        try:
            user = User.query.filter_by(username=username).first()

            if not user or not user.check_password(password):
                return jsonify({
                    'success': False,
                    'message': 'User name or password was wrong.'
                }), 401
            access_token = create_access_token(identity=user, expires_delta=False)          
                # session.clear()
            # session['user_id'] = user.id
            return jsonify({
                'success': True,
                'access_token':access_token
            })
        except Exception as error:
            abort(422)
    
    @app.route('/log_out', methods=['GET'])
    @jwt_required
    def log_out():
        
        return jsonify({
            'success': True
        })

    @app.route('/notes', methods=['POST'])
    @jwt_required()
    def note_index():
        # return render_template('note_index.html', notes=g.user.notes)
        user = User.query.filter_by(id=current_user.id).first_or_404()
        notes = user.notes
        formatted_notes = []
        for note in notes:
            formatted_notes.append({
                'id': note.id,
                'title': note.title,
                'body': note.body
            })
        print('notes: ', notes)
        return jsonify({
            'success': True,
            'notes': formatted_notes,
            'total_notes': len(formatted_notes)
        })

    @app.route('/notes/new', methods=['POST'])
    @jwt_required()
    def note_create():
        reqBody = request.get_json()
        title = reqBody.get('title')
        body = reqBody.get('body')
        error = None

        if not title:
            error = 'Title is required.'

        if not error:
            try:
                note = Note(user_id=current_user.id, title=title, body=body)
                db.session.add(note)
                db.session.commit()
                return jsonify({
                    'success': True
                })
            except Exception as error:
                abort(422)

    @app.route('/notes/<int:note_id>/edit', methods=['PATCH'])
    @jwt_required()
    def note_update(note_id):
        note = Note.query.filter_by(user_id=current_user.id, id=note_id).first_or_404()

        reqBody = request.get_json()
        title = reqBody.get('title')
        body = reqBody.get('body')
        error = None
        if not title:
            error = 'Title is required.'
        if not error:
            try:
                note.title = title
                note.body = body
                db.session.add(note)
                db.session.commit()
                return jsonify({
                    'success': True
                })
            except:
                abort(422)

    @app.route('/notes/<int:note_id>/delete', methods=['DELETE'])
    @jwt_required()
    def note_delete(note_id):
        try:
            note = Note.query.filter_by(user_id=current_user.id, id=note_id).first_or_404()
            db.session.delete(note)
            db.session.commit()
            return jsonify({
                'success': True
            })
        except:
            abort(422)

    @app.route('/')
    def index():
        return 'NOTES APP'

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            'success': False,
            'error': 404,
            'message': 'resource not found'
        }), 404

    @app.errorhandler(422)
    def unprocessable(error):
        return jsonify({
        "success": False, 
        "error": 422,
        "message": "unprocessable"
        }), 422

    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({
        "success": False, 
        "error": 400,
        "message": "bad request"
        }), 400

    # @app.errorhandler(AuthError)
    # def handle_auth_error(ex):
    #     response = jsonify(ex.error)
    #     response.status_code = ex.status_code
    #     return response

    @app.errorhandler(500)
    def server_error(error):
        return jsonify({
            "success": False,
            "error": 500,
            "message": "internal error"
        }), 500    

    return app