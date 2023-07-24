import os.path
import io
import base64
from datetime import datetime
from fastapi import APIRouter, Request, HTTPException, UploadFile, File, Depends
from database.connection import session
from database.models import *
from sqlalchemy import and_
from keygen.keys_generator import verify_otp, generate_qrcode, generate_secret_key
from app.jwt_settings import encode_token, decode_token
from fastapi.responses import FileResponse
from pydantic import BaseModel


ALLOWED_EXTENSIONS = {'png'}
UPLOAD_FOLDER = 'uploads'
router = APIRouter()


class EventCreateRequest(BaseModel):
    title: str
    date: str
    start_event: datetime
    end_event: datetime


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@router.get('/uploads/{filename}')
async def get_file(filename: str):
    file_path = os.path.join('uploads', filename)
    return FileResponse(file_path, filename=filename)


async def get_user_id(request: Request) -> str:
    token_data = decode_token(
            request.session.get('token'))
    if 'user_id' in token_data:
        return token_data['user_id']
    else:
        raise HTTPException(status_code=401, detail='User not authenticated')


@router.get('/@me')
async def me(request: Request):
    if 'token' in request.session:
        account = session.query(Account).filter(Account.user_id == decode_token(
            request.session.get('token'))['user_id']).first()
        return {
            'success': True,
            'name': account.name,
            'surname': account.surname,
            'photo': account.photo,
            'status': account.two_factor_auth
        }
    else:
        raise HTTPException(401, 'Not logged')


@router.post('/login')
async def login(request: Request):
    body = await request.json()
    username = body['username']
    password = body['passHex']
    otp = body['security_code']
    user = session.query(User).filter(and_(User.password == password, User.username == username)).first()
    print(user)
    if user is not None:
        account = session.query(Account).filter(Account.user_id == user.id).first()
        if account is not None:
            if account.two_factor_auth:
                if verify_otp(user.auth_key, otp):
                    request.session['token'] = encode_token(user.id)
                    return {'success': True, 'token': request.session.get('token')}
                else:
                    return {'success': False, 'message': 'Invalid OTP'}
            else:
                request.session['token'] = encode_token(user.id)
                return {'success': True, 'token': request.session.get('token')}
        else:
            account = Account(name='', surname='', user=user)
            session.add(account)
            session.commit()
            request.session['token'] = encode_token(user.id)
            return {'success': True, 'token': request.session.get('token')}
    else:
        raise HTTPException(401, 'Invalid data')


@router.post('/upload')
async def upload_file(file: UploadFile = File(...), user_id: str = Depends(get_user_id)):
    user_id = user_id
    folder_path = 'uploads/'
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    if allowed_file(file.filename):
        with open(f'uploads/{user_id}.png', 'wb') as f:
            f.write(await file.read())
        account = session.query(Account).filter(Account.user_id == int(user_id)).first()
        account.photo = str(user_id)+'.png'
        session.commit()
    else:
        raise HTTPException(422, 'Extension not valid')


@router.post('/logout')
async def logout(request: Request):
    request.session.clear()
    return {'Logged out'}


@router.get('/get_qrcode')
async def get_qr(request: Request):
    user_id = decode_token(request.session.get('token'))['user_id']
    user = session.query(User).filter(User.id == user_id).first()

    if user.auth_key:
        qr = generate_qrcode(username=user.username, secretkey=user.auth_key)
    else:
        key = generate_secret_key()
        user.auth_key = key
        session.commit()
        qr = generate_qrcode(username=user.username, secretkey=user.auth_key)

    image_io = io.BytesIO()
    qr.save(image_io)
    image_io.seek(0)
    image = image_io.getvalue()
    image_64 = base64.b64encode(image).decode('utf-8')
    return {'image': image_64}


@router.post('/set_2fa')
async def set_auth(request: Request):
    body = await request.json()
    user_id = decode_token(request.session.get('token'))['user_id']
    user = session.query(User).filter(User.id == user_id).first()
    secret_key = user.auth_key
    entered_otp = body['security_code']
    is_valid = verify_otp(secret_key, entered_otp)
    account = session.query(Account).filter(Account.user_id == user_id).first()

    if is_valid:
        account.two_factor_auth = True
        session.commit()
        return {'2FA set successfully'}
    else:
        raise HTTPException(401, '2FA setting error')


@router.post('/edit-data')
async def edit_data(request: Request):
    body = await request.json()

    if 'token' not in request.session:
        raise HTTPException(401, 'Unauthorized')

    user_id = decode_token(request.session.get('token'))['user_id']
    user = session.query(User).filter(User.id == user_id).first()
    account = session.query(Account).filter(Account.user_id == int(user_id)).first()
    name = body['name']
    surname = body['surname']

    if account is not None:
        account.name = name
        account.surname = surname
    else:
        account = Account(name=name, user=user, surname=surname)
        session.merge(account)
    session.commit()
    return {'Edited successfully'}


@router.post('/change-passwd')
async def change_password(request: Request):
    body = await request.json()
    password = body['old_password']
    new_password = body['new_password']
    user_id = decode_token(request.session.get('token'))['user_id']
    user = session.query(User).filter(User.id == user_id).first()
    if user.password == password:
        user.password = new_password
        session.commit()
        return {'Changed successfully'}
    else:
        raise HTTPException(401, 'Password not changed')


@router.post('/events')
async def create_event(request: Request):
    body = await request.json()
    user_id = decode_token(request.session.get('token'))['user_id']
    new_event = Events(user_id=user_id, title=body['title'], date=body['date'], start_event=body['start_event'],
                       end_event=body['end_event'])
    session.add(new_event)
    session.commit()
    return {'success': True}


@router.get('/events/{event_id}')
def get_event(event_id: int):
    event = session.query(Events).get(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.get('/events')
def get_all_events(request: Request):
    user_id = decode_token(request.session.get('token'))['user_id']
    events = session.query(Events).filter(Events.user_id == user_id).all()
    return events


@router.put('/events/{event_id}')
def update_event(event_id: int, event_data: EventCreateRequest):
    event = session.query(Events).get(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    event.title = event_data.title
    event.date = event_data.date
    event.start_event = event_data.start_event
    event.end_event = event_data.end_event
    session.commit()
    session.refresh(event)
    return event
