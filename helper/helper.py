# © Copyright IBM Corporation 2024

import sys
import ssl
import pathlib
from OpenSSL import crypto

"""
This module bundles together various py_zcrypto
   methods into simple and easy to use methods.
"""


def export_keypair(zcrypto_obj, cert_name, key_name, key_password, RACF_key_pair_label):
    """
    Exports a public/private key pair from a RACF keyring
    and converts both to pem format.
    Parameters:
       zcrypto_object : a py_zcrypto class object
       cert_name : the desired name of the certificate file
       key_name : the desired name of the key file
       key_password : password for key
       RACF_key_pair_label : the RACF label of an existing key pair
    Returns:
       Nothing. If successful, 4 files are created.
       2 certificates (der,pem) and 2 keys (der and pem)
    """

    if pathlib.Path(cert_name).suffix != "" or pathlib.Path(key_name).suffix != "":
        raise RuntimeError(
            """Pass in names for certificates
                              and key files without extensions"""
        )
        sys.exit(1)

    # These are the formats the cert/key come in from RACF.
    key_name += ".p12"
    cert_name += ".der"
    zcrypto_obj.export_key_to_file(key_name, key_password, RACF_key_pair_label)
    zcrypto_obj.export_cert_to_file(cert_name, RACF_key_pair_label)
    convert_der_cert_to_pem(cert_name)
    convert_p12_privatekey_to_pem(key_name, key_password)


def convert_p12_privatekey_to_pem(file_name, password):
    if not file_name.endswith(".p12"):
        raise ValueError("File must be .pkcs12 type")

    with open(file_name, "rb") as file:
        p12 = crypto.load_pkcs12(file.read(), password)

    with open("key.pem", "w") as file:
        file.write(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey()).decode(
                "utf-8"
            )
        )


def convert_der_cert_to_pem(file_name):
    if not file_name.endswith(".der"):
        raise ValueError("file must be .der type")

    with open(file_name, "rb") as f:
        file_name_der = f.read()

    file_name_pem = ssl.DER_cert_to_PEM_cert(file_name_der)

    with open(file_name.split(".")[0] + ".pem", "w") as f:
        f.write(file_name_pem)
