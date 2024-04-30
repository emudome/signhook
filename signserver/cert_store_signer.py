"""
Sign with a certificate in the Windows certificate store
"""
import json
from ctypes import WinDLL, string_at, Structure, POINTER, byref, create_unicode_buffer, c_ubyte
from ctypes.wintypes import DWORD, LPBYTE, HANDLE, BOOL, LPCWSTR, LPDWORD, LPBOOL
from signer import Signer

# pylint: disable-next=too-few-public-methods
class CertStoreSigner(Signer):
    """
    Class for signing with a certificate in the Windows certificate store
    """

    crypt32 = WinDLL("crypt32.dll")
    ncrypt = WinDLL("ncrypt.dll")

    CERT_STORE_PROV_SYSTEM = 10
    CERT_FIND_SUBJECT_STR = 0x00080007
    CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000
    X509_ASN_ENCODING = 0x00000001
    PKCS_7_ASN_ENCODING = 0x00010000
    CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG = 0x00040000
    BCRYPT_PAD_PKCS1 = 0x00000002
    ERROR_SUCCESS = 0

    # pylint: disable-next=missing-class-docstring, invalid-name, too-few-public-methods
    class CRYPT_DATA_BLOB(Structure):
        _fields_ = [("cbData", DWORD),
                    ("pbData", LPBYTE)]
    # pylint: disable-next=missing-class-docstring, invalid-name, too-few-public-methods
    class BCRYPT_PKCS1_PADDING_INFO(Structure):
        _fields_ = [("pszAlgId", LPCWSTR)]
    # pylint: disable-next=missing-class-docstring, invalid-name, too-few-public-methods
    class CERT_CONTEXT(Structure):
        _fields_ = [("dwCertEncodingType", DWORD),
                    ("pbCertEncoded", LPBYTE),
                    ("cbCertEncoded", DWORD),
                    ("pCertInfo", HANDLE),
                    ("hCertStore", HANDLE)]

    crypt32.CertOpenStore.restype = HANDLE
    crypt32.CertOpenStore.argtypes = [HANDLE, DWORD, HANDLE, DWORD, LPCWSTR]

    crypt32.CertFindCertificateInStore.restype = POINTER(CERT_CONTEXT)
    crypt32.CertFindCertificateInStore.argtypes = [HANDLE, DWORD, DWORD, DWORD, LPCWSTR, HANDLE]

    crypt32.CertCloseStore.restype = BOOL
    crypt32.CertCloseStore.argtypes = [HANDLE, DWORD]

    crypt32.CryptAcquireCertificatePrivateKey.restype = BOOL
    crypt32.CryptAcquireCertificatePrivateKey.argtypes = [HANDLE, DWORD, HANDLE, HANDLE, LPDWORD, LPBOOL]

    def __init__(self, config_file):
        self.config_file = config_file

    def _get_certificate_from_store(self, subject):
        """
        Get a certificate with the specified subject name from the certificate store
        """
        h_store = self.crypt32.CertOpenStore(self.CERT_STORE_PROV_SYSTEM, 0, None,
                                             self.CERT_SYSTEM_STORE_CURRENT_USER, "MY")
        if not h_store:
            raise RuntimeError("Failed to open certificate store.")
        subject_unicode = create_unicode_buffer(subject)
        cert_context = self.crypt32.CertFindCertificateInStore(
            h_store, self.X509_ASN_ENCODING | self.PKCS_7_ASN_ENCODING, 0,
            self.CERT_FIND_SUBJECT_STR, subject_unicode, None)
        self.crypt32.CertCloseStore(h_store, 0)
        if not cert_context:
            raise RuntimeError("Certificate not found.")
        return cert_context

    def _sign_data_with_cng(self, data, cert_context, digest_algorithm):
        """
        Sign the specified hash data with the specified certificate
        """
        h_key = HANDLE()
        key_spec = DWORD()
        free_prov_or_n_key = BOOL()

        if not self.crypt32.CryptAcquireCertificatePrivateKey(
                cert_context, self.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, None,
                byref(h_key), byref(key_spec), byref(free_prov_or_n_key)):
            raise RuntimeError("Failed to acquire private key from certificate.")

        padding_info = self.BCRYPT_PKCS1_PADDING_INFO(digest_algorithm)
        signature_length = DWORD()
        if self.ncrypt.NCryptSignHash(
                h_key, byref(padding_info), data, len(data), None,
                0, byref(signature_length), self.BCRYPT_PAD_PKCS1) != self.ERROR_SUCCESS:
            self.ncrypt.NCryptFreeObject(h_key)
            raise RuntimeError("Failed to create signature.")

        signed_blob = (c_ubyte * signature_length.value)()
        if self.ncrypt.NCryptSignHash(
                h_key, byref(padding_info), data, len(data),
                byref(signed_blob), signature_length,
                byref(signature_length), self.BCRYPT_PAD_PKCS1) != self.ERROR_SUCCESS:
            self.ncrypt.NCryptFreeObject(h_key)
            raise RuntimeError("Failed to sign data.")
        self.ncrypt.NCryptFreeObject(h_key)
        return bytes(signed_blob)

    def sign(self, digest, digest_algorithm):
        """
        Sign with a certificate in the Windows certificate store
        """
        with open(self.config_file, "r", encoding="utf-8") as f:
            config = json.load(f)

        # Get a certificate from the certificate store
        cert_subject = config["cert_subject"]
        cert_context = self._get_certificate_from_store(cert_subject)
        if not cert_context:
            raise RuntimeError("Certificate retrieval failed")

        # Sign the hash value (digest value)
        signed_digest = self._sign_data_with_cng(digest, cert_context, digest_algorithm)
        if not signed_digest:
            raise RuntimeError("Data signing failed")

        # Convert the certificate to a byte array
        encoded_cert = string_at(
            cert_context.contents.pbCertEncoded,
            cert_context.contents.cbCertEncoded)

        return signed_digest, encoded_cert, cert_context.contents.dwCertEncodingType

    def close(self):
        """
        Release resources
        """
