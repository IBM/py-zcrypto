# Python-Zcrypto

This Python package provides API's to access [Certificate Management Services (CMS).](https://www.ibm.com/docs/en/zos/2.5.0?topic=programming-certificate-management-services-cms-api-reference) The APIs in this module can be used to create/manage your own key database files, and extract certificates stored in the key database file or RACF key ring. The helper package is installed alongside python zcrypto, and is only used to bundle together functionality. 

## Setup
It's best practice to install in a clean virtual environment with `--system-site-packages` to get access to other needed dependencies (cffi, cryptography, six, pycparser) required by pyOpenSSL.

A C compiler is required to install this package from source. See [this](https://www.ibm.com/docs/en/python-zos/3.12?topic=using-cc-compilers-open-enterprise-sdk-python-312) page for supported compilers and required environment variables to use them.

```
# Install from PyPI
python3 -m venv venv --system-site-packages
source venv/bin/activate
pip3 install py_zcrypto
```

```
# Install from local
python3 -m venv venv --system-site-packages
source venv/bin/activate
pip3 install ./py-zcrypto
```

## Usage
### The `get_keypair` method shows how to get a public/private keypair using zcrypto. 
```
import py_zcrypto
from helper import export_keypair
from py_zcrypto import zcrypto

def get_keypair(ring_name, cert_name, key_name, password, keypair_name):
    '''
    Export keypair method will export the public/private keypair
    from your RACF keyring and convert the encoding to pem.
    Parameters:
         zcrypto_object (zcrypto) : A zcrypto object
         cert_name (string) : String name for the certificate file
         key_name (String) : String name for the key file
         password (String) : String password for the keyfile
         keypair_name (String) : String name for the public/private
                                 keypair from RACF
    Returns:
         Nothing. If successful will create 4 files;
         cert and key files (pem and der encoded)
    '''
    py_zcrypto_obj = zcrypto()
    try:
        py_zcrypto_obj.open_key_ring(ring_name)
    except py_zcrypto.GSKError as e:
        print(str(e))
        return

    export_keypair(py_zcrypto_obj, cert_name, key_name, password, keypair_name)

    py_zcrypto_obj.close_database()
    
```
## The `get_certificate_fromRACF` method shows how to export a CA certificate.
```
import sys
import py_zcrypto
from helper import convert_der_cert_to_pem

def get_certificate_fromRACF():
    '''
    Export a CA certificate from a RACF keyring and convert
    encoding to pem.
    Returns:
        return 0 if successful along with a der and pem encoded CA certificate.
    '''
    
    py_zcrypto_obj = py_zcrypto.zcrypto()
    try:
        py_zcrypto_obj.open_key_ring("ring_name")
    except py_zcrypto.GSKError as e:
        print(str(e))
        return

    try:
        py_zcrypto_obj.export_cert_to_file("public_key_file.der",
                                            "CACert_name")
    except py_zcrypto.GSKError as e:
        print(str(e))
        return

    convert_der_cert_to_pem("public_key_file.der")
    return
```
## Notes
- Error codes are Certificate Management Services (CMS) status codes in decimal format. These codes can be found in the header gskcms.h.

- Additional details about the Certificate Management Services (CMS) API can be found [here] (https://www.ibm.com/docs/en/zos/2.5.0?topic=programming-certificate-management-services-cms-api-reference)
- Only use the pem encoded versions of certificates/public/private keys for python purposes.

## Docstrings
To view a function docstring, type the method name followed by .doc
```
print(Pythonzcrypto.__doc__)
```
To view all methods available, read the package docstring:
```
python3 -c "import py_zcrypto; print(help(py_zcrypto))"
python3 -c "import helper; print(help(helper.helper))"
```

