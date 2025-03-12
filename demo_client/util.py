import base64

def b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def b64_decode(s) -> bytes:
    padding = '=' * (len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)

