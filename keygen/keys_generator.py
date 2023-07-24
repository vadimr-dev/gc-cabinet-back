import pyotp
import qrcode

secret_key = pyotp.random_base32()


def generate_secret_key():
    return pyotp.random_base32()


def generate_qrcode(username, secretkey):
    totp = pyotp.totp.TOTP(secretkey)
    otpauth_url = totp.provisioning_uri(username,
                                        issuer_name="Golden Community")
    qr = qrcode.QRCode(version=1,
                       error_correction=qrcode.constants.ERROR_CORRECT_L,
                       box_size=10, border=4)
    qr.add_data(otpauth_url)
    qr.make(fit=True)
    img = qr.make_image(back_color="black", fill_color=(145, 108, 33))
    return img


def verify_otp(secretkey, otp):
    totp = pyotp.TOTP(secretkey)
    return totp.verify(otp)
