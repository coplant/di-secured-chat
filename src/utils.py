import rsa

from src.config import PUBLIC_KEY, PRIVATE_KEY, HASH_TYPE


# RSA Keys
def get_public_key() -> rsa.PublicKey:
    if PUBLIC_KEY.is_file():
        with open(PUBLIC_KEY, "rb") as file:
            public_key = rsa.PublicKey.load_pkcs1(file.read(), format="DER")
        return public_key


def get_private_key() -> rsa.PrivateKey:
    if PRIVATE_KEY.is_file():
        with open(PRIVATE_KEY, "rb") as file:
            private_key = rsa.PrivateKey.load_pkcs1(file.read(), format="DER")
        return private_key


def get_keys() -> (rsa.PublicKey, rsa.PrivateKey):
    public_key = get_public_key()
    private_key = get_private_key()
    return public_key, private_key


def setup_keys() -> (rsa.PublicKey, rsa.PrivateKey):
    public_key, private_key = rsa.newkeys(1024)
    with open(PUBLIC_KEY, "wb") as file:
        file.write(public_key.save_pkcs1(format="DER"))
    with open(PRIVATE_KEY, "wb") as file:
        file.write(private_key.save_pkcs1(format="DER"))
    return public_key, private_key


# is valid signature
def is_valid_signature(message, signature, public_key):
    try:
        return rsa.verify(message, signature, public_key) == HASH_TYPE
    except rsa.pkcs1.VerificationError:
        return False
