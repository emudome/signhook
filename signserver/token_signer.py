"""
Sign with a USB token
"""
import json
import PyKCS11
import PyKCS11.LowLevel as PKCS
from signer import Signer

class USBTokenSigner(Signer):
    """
    USB token signature class
    """
    def __init__(self, config_file):
        # Read settings from setting.json
        with open(config_file, "r", encoding="utf-8") as f:
            self.config = json.load(f)

        # Load PKCS#11 library
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(self.config["dll_path"])

        # Get slot list
        self.slots = self.pkcs11.getSlotList(tokenPresent=True)
        if not self.slots:
            raise RuntimeError("No token found")

        # Open the slot where the USB token is inserted (usually slot 0, but may vary depending on the environment)
        self.session = self.pkcs11.openSession(self.slots[self.config["slot_number"]])
        self.session.login(self.config["pin"])

        # Get private key handle
        self.private_key = self.session.findObjects(
            [(PKCS.CKA_CLASS, PKCS.CKO_PRIVATE_KEY),
             (PKCS.CKA_LABEL, self.config["key_label"])])[0]

    def sign(self, digest, digest_algorithm):
        """
        Sign the data
        """
        # Set the signature mechanism
        algorithm_to_mechanism = {
            "SHA1":   PKCS.CKM_SHA1_RSA_PKCS,
            "SHA256": PKCS.CKM_SHA256_RSA_PKCS,
            "SHA384": PKCS.CKM_SHA384_RSA_PKCS,
            "SHA512": PKCS.CKM_SHA512_RSA_PKCS
        }
        mechanism_type = algorithm_to_mechanism[digest_algorithm]
        mechanism = PyKCS11.Mechanism(mechanism_type, None)

        # Sign the hash value (digest value)
        signed_digest = bytes(self.session.sign(self.private_key, digest, mechanism))

        # Get certificate data
        certificate = self.session.findObjects(
            [(PKCS.CKA_CLASS, PKCS.CKO_CERTIFICATE),
             (PKCS.CKA_LABEL, self.config["cert_label"])])[0]

        # Get X.509 DER encoded certificate
        encoded_cert = bytes(self.session.getAttributeValue(certificate, [PKCS.CKA_VALUE])[0])

        return signed_digest, encoded_cert, 1

    def close(self):
        """
        Close the session
        """
        self.session.logout()
        self.session.closeSession()
