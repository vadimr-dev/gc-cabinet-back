import jwt

JWT_SECRET = "aosudyasigdkasgdkahs"
JWT_ALGORITHM = "HS256"


def encode_token(user_id: int):
    payload = {
        "user_id": user_id
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return token


def decode_token(token: str):
    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if 'user_id' in decoded_token:
            return decoded_token
        else:
            return None
    except:
        return None
