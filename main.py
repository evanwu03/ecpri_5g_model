
# Author: Evan Wu
# Date of Revision: 6/9/2026



from scapy.all import *
import logging
from ecpri import *


# Set log level to INFO to take advantage of Scapy warnings
logger = logging.getLogger("scapy")
logger.setLevel(logging.INFO)


def build_concat_ecpri_frame(ecpri_messages: List, dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55"):
    payload = b"".join(bytes(msg) for msg in ecpri_messages)

    return (
        Ether(dst=dst, src=src, type=ECPRI_ETHERTYPE)
        / Raw(payload)
    )

def main() -> None:
    # DEBUG: Open scapy interactive terminal
    #interact(mydict=globals())

    # Small demo to show that ECPRI packet (with message type 0) 
    # over Ethernet will be interpreted as an ECPRI message by Scapy
    msg0 = (
        ECPRI(
            protocol_revision=2,
            c=1,
            msg_type=ECPRIMsgType.REAL_TIME_CONTROL_DATA,
        )
        / ECPRI_RTC_MSG(
            RTC_ID=6,
            SEQ_ID=7,
            data=b"\x11" * 4,
        )
    )

    msg1 = (
        ECPRI(
            protocol_revision=2,
            c=1,
            msg_type=ECPRIMsgType.IQ_DATA,
        )
        / ECPRI_IQ_DATA_MSG(
            PC_ID=6,
            SEQ_ID=7,
            data=b"\x22" * 2
        )
    )

    msg2 = (
        ECPRI(
            protocol_revision=2,
            c=0,
            msg_type=ECPRIMsgType.IQ_DATA,
        )
        / ECPRI_IQ_DATA_MSG(
            PC_ID=6,
            SEQ_ID=7,
            data=b"\x88" * 8
        )
    )

    msgs = [msg0, msg1, msg2]
    ecpri_msgs = build_concat_ecpri_frame(msgs)

    decoded = Ether(bytes(ecpri_msgs))
    decoded.show()
    
    print(hexdump(decoded))

    # Export to PCAP file
    wrpcap("concat_ecpri_msg.cap", ecpri_msgs)

if __name__=="__main__":
    main()