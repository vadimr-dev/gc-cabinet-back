from sqlalchemy import text
import os
import io
import base64
from werkzeug.utils import secure_filename
from flask import send_from_directory, request, session, jsonify
from app.database.models import *
from . import pages
from flask_jwt_extended import create_access_token, decode_token
from ..keygen.keys_generator import generate_secret_key, generate_qrcode, verify_otp

ALLOWED_EXTENSIONS = {'png'}
UPLOAD_FOLDER = 'uploads'


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@pages.route('/@me', methods=['GET'])
def me():
    if 'token' in session:
        user = Account.query.filter_by(user_id=decode_token(session.get('token'))['sub']).first()
        return jsonify({'success': True,
                        'name': user.name,
                        'surname': user.surname,
                        'info': user.info,
                        'photo': user.photo,
                        'status': user.two_factor_auth
                        })
    else:
        return jsonify({'success': False}), 401


@pages.route('/uploads/<path:path>')
def send_image(path):
    return send_from_directory(UPLOAD_FOLDER, path)


@pages.route('/get_qrcode')
def get_qr():
    user_id = decode_token(session.get('token'))['sub']
    user = User.query.filter_by(id=user_id).first()
    if user.auth_key:
        qr = generate_qrcode(username=user.username, secretkey=user.auth_key)
    else:
        key = generate_secret_key()
        user.auth_key = key
        db.session.commit()
        qr = generate_qrcode(username=user.username, secretkey=user.auth_key)
    image_io = io.BytesIO()
    qr.save(image_io)
    image_io.seek(0)
    image = image_io.getvalue()
    image_64 = base64.b64encode(image).decode('utf-8')
    return jsonify(image=image_64)


@pages.route('/set_2fa', methods=['POST'])
def set_auth():
    user_id = decode_token(session.get('token'))['sub']
    user = User.query.filter_by(id=user_id).first()
    secret_key = user.auth_key
    entered_otp = request.json['security_code']
    is_valid = verify_otp(secret_key, entered_otp)
    account = Account.query.filter_by(user_id=user.id).first()
    if is_valid:
        account.two_factor_auth = True
        db.session.commit()
        return '200'
    else:
        return '401'


@pages.route('/verify_code', methods=['POST'])
def verify():
    user_id = decode_token(session.get('token'))['sub']
    user = User.query.filter_by(id=user_id).first()
    secret_key = user.auth_key
    entered_otp = request.json['security_code']

    is_valid = verify_otp(secret_key, entered_otp)

    if is_valid:
        print(True)
        return '200'
    else:
        print(False)
        return '404'


@pages.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    if file and allowed_file(file.filename):
        ext = file.filename.split('.')
        filename = secure_filename(str(decode_token(session.get('token'))['sub'])+'.'+ext[len(ext)-1])
        file.save(os.path.join('app', UPLOAD_FOLDER, filename))
        account = Account.query.filter_by(user_id=decode_token(session.get('token'))['sub']).first()
        account.photo = filename
        db.session.commit()
        return '200'
    return '401'


@pages.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        username = request.json['username']
        password = request.json['passHex']
        otp = request.json['security_code']

        user = User.query.filter_by(username=username, password=password).first()
        if user is not None:
            account = Account.query.filter_by(user_id=user.id).first()
            if account is not None:
                if account.two_factor_auth:
                    if verify_otp(user.auth_key, otp):
                        session['token'] = create_access_token(identity=user.id)
                        return jsonify({'success': True, 'token': session.get('token')}), 200
                    else:
                        return jsonify({'success': False, 'message': 'Invalid OTP'}), 200
                else:
                    session['token'] = create_access_token(identity=user.id)
                    return jsonify({'success': True, 'token': session.get('token')}), 200
            else:
                account = Account(name='', surname='', info='', user=user)
                db.session.add(account)
                db.session.commit()
                return jsonify({'success': True, 'token': session.get('token')}), 200
        else:
            return jsonify({'success': False, 'message': 'Invalid data'}), 401


@pages.route('/edit-data', methods=['POST'])
def edit_data():
    if 'token' not in session:
        return '401'

    user_id = decode_token(session.get('token'))['sub']
    user = User.query.filter_by(id=user_id).first()
    account = Account.query.filter_by(user=user).first()
    name = request.json['name']
    surname = request.json['surname']
    info = request.json['info']

    if account is not None:
        account.name = name
        account.surname = surname
        account.info = info
    else:
        account = Account(name=name, surname=surname, info=info, user=user)
        db.session.merge(account)
    db.session.commit()
    return '200'


@pages.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return '200'


@pages.route('/calendar/events', methods=['GET'])
def get_events():
    data = []
    sql = f"SELECT id, title, start_event, end_event FROM events " \
          f"WHERE user_id = {decode_token(session.get('token'))['sub']};"
    with db.engine.connect() as conn:
        events = conn.execute(text(sql)).fetchall()
    for i in events:
        one = {
            'id': i[0],
            'title': i[1],
            'start':  i[2],
            'end': i[3]
        }
        data.append(one)
    return jsonify(data)


@pages.route('/calendar/events', methods=['POST'])
def add_event():
    data = request.json
    print(data)
    event = Events(user_id=decode_token(session.get('token'))['sub'], title=data['title'],
                   start_event=data['start'], end_event=data['end'])
    db.session.add(event)
    db.session.commit()
    data['id'] = event.id
    return jsonify(data)


@pages.route('/calendar/update/<int:event_id>', methods=['POST'])
def update(event_id):
    data = request.json
    event = Events.query.filter_by(id=event_id).first()
    event.start_event = data['start']
    event.end_event = data['end']
    db.session.merge(event)
    db.session.commit()
    return jsonify(data)


@pages.route('/calendar/delete/<int:event_id>', methods=['POST'])
def delete(event_id):
    event = Events.query.filter_by(id=event_id).first()
    db.session.delete(event)
    db.session.commit()
    return '200'


@pages.route('/change-passwd', methods=['POST'])
def change_password():
    password = request.json['old_password']
    new_password = request.json['new_password']
    user = User.query.filter_by(id=decode_token(session.get('token'))['sub']).first()
    if user.password == password:
        user.password = new_password
        db.session.commit()
        return '200'
    else:
        return '401'
