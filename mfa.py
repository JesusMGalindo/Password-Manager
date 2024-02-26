import pyotp
import qrcode
from PIL import Image
from keys import MFAKEY


def addUserToMFA(username):
    url = pyotp.totp.TOTP(MFAKEY).provisioning_uri(name=username, issuer_name="Password Management App")

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)

    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_img.show()

def isUserValid(inputtedCode):
    totp = pyotp.TOTP(MFAKEY)
    return totp.verify(inputtedCode)