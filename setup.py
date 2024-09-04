# © Copyright IBM Corporation 2024

from setuptools import setup, Extension, find_packages
import sys

def main():
    setup_requirements = ["pyopenssl<=21.0.0"]
    extension_modules = [
        Extension(
            "py_zcrypto",
            ["./src/zcrypto.c", "./src/zcrypto_impl.c"],
            ["/usr/lpp/gskssl/include"],
            extra_link_args=[
                "/usr/lpp/gskssl/lib/GSKCMS64.x",
                "/usr/lpp/gskssl/lib/GSKSSL64.x",
            ],
        )
    ]

    setup(
        name="py_zcrypto",
        version="1.0.0",
        description="Python interface for accessing RACF Keyrings and key databases on z/OS",
        author="IBM",
        packages=find_packages(),
        install_requires=setup_requirements,
        ext_modules=extension_modules,
    )


if __name__ == "__main__":
    main()
