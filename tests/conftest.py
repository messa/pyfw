import logging
import sys


logging.basicConfig(
    format='- %(levelname)5s: %(message)s',
    level=logging.DEBUG,
    stream=sys.stdout)
