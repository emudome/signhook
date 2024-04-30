"""
This module provides a Flask web application for signing hash data using different signing modes.

It defines a Signer class that initializes the signing mode based on the configuration file provided.
The Signer class has a sign method that takes in hash data and a digest algorithm, and returns the signed digest,
encoded certificate, and certificate encoding type.

The Flask application defines a route "/sign" that accepts POST requests for signing hash data.
It retrieves the digest algorithm from the request arguments, calls the sign method of the Signer instance,
and returns the signed digest, encoded certificate, and certificate encoding type as a JSON response.

Usage:
- Run the Flask application by executing this script.
- Send a POST request to http://localhost:5000/sign with the hash data in the request body.
- Optionally, include the "digest_algorithm" query parameter to specify the digest algorithm (default is SHA256).
"""

import json
import logging
import signal
import sys
from flask import Flask, request, jsonify

from cert_store_signer import CertStoreSigner
from token_signer import USBTokenSigner

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# pylint: disable-next=too-few-public-methods
class SignerFactory:
    """
    Factory class for creating Signer instances based on the configuration file.
    """
    @staticmethod
    def create(config_file):
        """
        Create a Signer instance based on the configuration file.

        Args:
            config_file (str): Path to the configuration file.

        Returns:
            Signer: A Signer instance based on the specified signing mode.

        Raises:
            ValueError: If the signing mode is not recognized.
        """
        with open(config_file, "r", encoding="utf-8") as f:
            config = json.load(f)
        sign_mode = config.get("sign_mode", "cert_store")
        if sign_mode == "cert_store":
            return CertStoreSigner(config_file)
        elif sign_mode == "usb_token":
            return USBTokenSigner(config_file)
        else:
            raise ValueError("Unsupported signing mode")

signer = SignerFactory.create("setting.json")

def signal_handler(_, __):
    """
    Handles the signal by closing the signer and exiting the program.
    """
    signer.close()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

@app.route("/sign", methods=["POST"])
def sign_data():
    """
    Sign the hash data based on the request parameters.

    Returns:
        flask.Response: A JSON response containing the signed digest, encoded certificate,
                        and certificate encoding type.

    Raises:
        RuntimeError: If an error occurs during the signing process.
    """
    digest_algorithm = request.args.get("digest_algorithm", "SHA256")

    try:
        signed_digest, encoded_cert, cert_encoding_type \
             = signer.sign(request.data, digest_algorithm)
        return jsonify({
            "signed_digest": signed_digest.hex(),
            "encoded_cert": encoded_cert.hex(),
            "cert_encoding_type": cert_encoding_type
            })
    except RuntimeError as e:
        logging.error(str(e))
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=False, port=5000)
