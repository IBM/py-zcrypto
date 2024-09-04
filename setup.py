# © Copyright IBM Corporation 2024

from setuptools import setup, Extension, find_packages
import sys

def main():
    setup_requirements = ["pyopenssl<=21.0.0"]
    extension_modules = [
        Extension(
            "py_zcrypto",
            ["./src/zcrypto.c", "./src/zcrypto_impl.c"],
            ["./src", "/usr/lpp/gskssl/include"],
            extra_link_args=[
                "/usr/lpp/gskssl/lib/GSKCMS64.x",
                "/usr/lpp/gskssl/lib/GSKSSL64.x",
            ],
            depends=[
                "src/zcrypto.h"
            ],
        )
    ]

    project_description = None
    with open('README.md', 'r') as f:
        project_description = f.read()

    setup(
        name="py_zcrypto",
        version="1.0.1",
        description="Python interface for accessing RACF Keyrings and key databases on z/OS",
        long_description=project_description,
        long_description_content_type='text/markdown',
        license="License :: OSI Approved :: Apache Software License",
        project_urls={
            "Source Code": "https://github.com/IBM/py-zcrypto/",
          },
        author="IBM",
        packages=find_packages(),
        install_requires=setup_requirements,
        ext_modules=extension_modules,
    )


if __name__ == "__main__":
    main()
