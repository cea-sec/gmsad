import configparser
import logging

REQUIRED_ACCOUNT_KEYS = [
    "principal", # Principal allowed to retrieve the gMSA account
    "keytab", # Keytab file containg secrets for <principal>
    "gMSA_sAMAccountName", # sAMAccountName of the gMSA account
    "gMSA_domain", # AD domain name of the gMSA account
    "gMSA_keytab", # Keytab file where gMSA account keys will be stored
]

def load_config(filename: str) -> configparser.ConfigParser:
    """
    Load configuration using configparser and check
    the existence of required parameters
    """
    config = configparser.ConfigParser(
            converters={'list': lambda x: [i.strip() for i in x.split(',')]}
    )
    try:
        with open(filename, "r") as fd:
            config.read_file(fd)
    except FileNotFoundError as e:
        logging.critical("Config file %s does not exist: %s", filename, e)
        raise

    for section in config.sections():
        if section == 'gmsad':
            continue
        # TODO: Add checks for supported gMSA_enctypes values
        for key in REQUIRED_ACCOUNT_KEYS:
            if not config.has_option(section, key):
                raise ValueError(f"Missing key {key} in section {section} of config file")
    return config
