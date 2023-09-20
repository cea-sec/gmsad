import configparser
import logging
import traceback

from gmsad.utils import every
from gmsad.gmsa import GMSAState
from gmsad.keytab import Keytab

def run(config: configparser.ConfigParser) -> int:
    state = init_state(config)
    for gmsa in state.values():
        gmsa.update()
    every(config.getint("gmsad", "check_interval", fallback=60),
            update_loop, config, state)
    # This should never return
    return 0


def update_loop(config: configparser.ConfigParser, state: dict) -> None:
    for name, gmsa in state.items():
        try:
            gmsa.update()
        except Exception as e:
            logging.critical("An error occurred while updating %s: %s", name, e)
            logging.debug(traceback.format_exc())


def init_state(config: configparser.ConfigParser) -> dict:
    state = {}
    # It is possible to store the secrets of multiple GMSAs in a single keytab file.
    # For this to work, each keytab file must be managed by a single "Keytab" instance.
    keytabs = {}
    for section in config.sections():
        if section == 'gmsad':
            continue
        keytab_path = config[section]['gMSA_keytab']
        if not keytab_path in keytabs:
            keytab = Keytab()
            keytab.open(keytab_path)
            keytabs[keytab_path] = keytab
        state[section] = GMSAState(config[section], keytabs[keytab_path])
    return state
