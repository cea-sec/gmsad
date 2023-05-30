from setuptools import setup, find_packages

# read the contents of your README file
# cf https://packaging.python.org/en/latest/guides/making-a-pypi-friendly-readme/
from pathlib import Path
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name='gmsad',
    version='0.1.0',
    author='Vincent Ruello',
    author_email='vincent.ruello@cea.fr',
    description="Linux service to manage gMSA accounts",
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=find_packages(exclude=['tests']),
    entry_points={
        'console_scripts': [
            'gmsad = gmsad.bin.gmsad:main'
        ]
    },
    install_requires = [
        'ldap3',
        'gssapi',
        'dnspython',
        'pycryptodomex',
        'asn1crypto',
    ],
    extras_require={
        'dev': [
            'mypy'
        ]
    },
    test_suite='tests',
)
