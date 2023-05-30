import logging
import time
from typing import Callable, Any
import dns.resolver

def every(delay: int, task: Callable, *args: Any, **kwargs: Any) -> None:
    """
    Execute task(*args, **kwargs) every <delay> seconds
    If task crashes, logs the error and continue.
    """
    next_time = time.time() + delay
    while True:
        time.sleep(max(0, next_time - time.time()))
        try:
            task(*args, **kwargs)
        except Exception as e:
            logging.error("An error occurred in %s: %s", task.__name__, e)
        # We want to execute task at regular interval
        task_duration = time.time() - next_time
        task_duration_aligned_on_delay = (task_duration // delay) * delay
        time_to_wait = task_duration_aligned_on_delay + delay
        next_time += time_to_wait


def configure_logging(loglevel_str: str) -> None:
    """
    Configure logging utility
    """
    loglevel = getattr(logging, loglevel_str, None)
    if not isinstance(loglevel, int):
        raise ValueError(f"Invalid log level: {loglevel_str}")
    logging.basicConfig(level=loglevel, force=True)
    logging.info("Log level is set to %s", loglevel_str)


def dns_query(domain: str, dns_type: str) -> str:
    """
    Execute a DNS query and returns the first result
    """
    try:
        res = dns.resolver.query(domain, dns_type)
    except dns.resolver.NoNameservers:
        res = dns.resolver.query(domain, dns_type, tcp=True)
    return str(res[0].target).rstrip('.').lower()


def get_dc(domain: str) -> str:
    return dns_query(f"_ldap._tcp.pdc._msdcs.{domain}", "SRV")
