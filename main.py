
# Author: Evan Wu
# Date of Revision: 6/9/2026



from scapy.all import *
import logging

# Set log level to INFO to take advantage of Scapy warnings
logger = logging.getLogger("scapy")
logger.setLevel(logging.INFO)


def main() -> None:
    interact(mydict=globals())


if __name__=="__main__":
    main()