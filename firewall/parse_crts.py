from base64 import b64decode, b64encode
from typing import List
from cryptography import x509
from cryptography.hazmat.backends import default_backend
class TlsHandshakeCerts():
    def __init__(self, data:bytes) -> None:
        self.certs:List[x509.Certificate] = []
        _data = data[::]

        while len(_data) != 0:
            crt_len = int.from_bytes(_data[:3], "big")
            print("crt_len:", crt_len)
            crt_bytes = _data[3:3+crt_len]
            _data = _data[3+crt_len:]
            res_crt = b"-----BEGIN CERTIFICATE-----\n" + b64encode(crt_bytes) + b"\n-----END CERTIFICATE-----"
            self.certs.append(
                x509.load_pem_x509_certificate(res_crt, default_backend())
            )
            from pprint import pprint
            pprint(self.certs[-1])