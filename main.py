
# Author: Evan Wu
# Date of Revision: 6/9/2026



from scapy.all import *
import logging
from ecpri import *


# Set log level to INFO to take advantage of Scapy warnings
logger = logging.getLogger("scapy")
logger.setLevel(logging.INFO)


def main() -> None:
    # DEBUG: Open scapy interactive terminal
    #interact(mydict=globals())


    # Small demo to show that ECPRI packet (with message type 0) 
    # over Ethernet will be interpreted as an ECPRI message by Scapy
    """
    pkt = (
    Ether(
        dst="ff:ff:ff:ff:ff:ff",
        src="00:11:22:33:44:55",
        type=ECPRI_ETHERTYPE,
    )
    / ECPRI(
        protocol_revision=1,
        c=1,
        msg_type=0,
        #payload_size=4,
    )
    / ECPRI_IQ_DATA_MSG(
        PC_ID = 6,
        SEQ_ID = 7,
        data = b"\x11\x11\x11\x11\x11\x11\x11\x11\x11"
    )
    )
    """


    pkt = (
    Ether(
        dst="ff:ff:ff:ff:ff:ff",
        src="00:11:22:33:44:55",
        type=ECPRI_ETHERTYPE,
    )
    / ECPRI(
        protocol_revision=1,
        c=1,
        msg_type=ECPRIMsgType.REAL_TIME_CONTROL_DATA,
        #payload_size=4,
    )
    / ECPRI_RTC_MSG(
        RTC_ID = 6,
        SEQ_ID = 7,
        data = b"\x11\x11\x11\x11\x11\x11\x11\x11\x11"
    )
    )

    pkt.show()
    print(bytes(pkt).hex())

    decoded = Ether(bytes(pkt))
    decoded.show()
    


if __name__=="__main__":
    main()