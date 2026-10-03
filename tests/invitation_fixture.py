import base64,hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import nhp

def key_delivery(expires=2000000000):
    private=X25519PrivateKey.from_private_bytes(hashlib.sha256(b"synthetic invitation key fixture").digest())
    raw=private.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
    public=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    return {"private_key":base64.urlsafe_b64encode(raw).decode().rstrip("="),"public_key":base64.b64encode(public).decode(),"invitation_id":hashlib.sha256(public).hexdigest(),"landing_url":nhp.LANDING_ORIGIN+"/","expires":expires}
