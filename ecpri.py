# Author: Evan Wu
# Date of Revision: 6/9/2026

from scapy.all import (
    Packet, 
    BitField, 
    ByteEnumField, 
    ShortField, Ether, 
    StrLenField,
    bind_layers
)

ECPRI_ETHERTYPE = 0xAEFE

ECPRI_MSG_TYPES = { 
    0: "IQ Data",
    1: "Bit Sequence",
    2: "Real-Time Control Data",
    3: "Generic Data Transfer",
    4: "Remote Memory Access",
    5: "One-way Delay Measurement",
    6: "Remote Reset",
    7: "Event Indication",
    8: "IWF Start-Up",
    9: "IWF Operation",
    10: "IWF Mapping",
    11: "IWF Delay Control",
    **{i: "Reserved" for i in range(12, 64)},
    **{i: "Vendor Specific" for i in range(64, 256)},
}

def pad_len_to_4_bytes(payload_size: int) -> int:
    remainder = payload_size % 4
    return (4 - remainder)


class ECPRI(Packet):
    name = "ECPRI"

    # ECPRI follows Big-endian ordering (MSB --> LSB)
    fields_desc = [
        BitField("protocol_revision", 1, 4),
        BitField("reserved", 0, 3), 
        BitField("c", 0, 1), #  Concatenation indicator
        ByteEnumField("msg_type", 0, ECPRI_MSG_TYPES), 
        ShortField("payload_size", None) # max payload size is 2^16-1 bytes 
    ]

    def post_build(self, pkt, pay):
        # pkt = bytes of this ECPRI layer only
        # pay = bytes of all layers after ECPRI
        pkt += pay
        payload_len = len(pay)

        # If user did not manually set payload_size, compute it.
        if self.payload_size is None:
            payload_size = payload_len

            # eCPRI payload_size occupies bytes 2 and 3 of the common header.
            pkt = (
                pkt[:2]
                + payload_size.to_bytes(2, byteorder="big")
                + pkt[4:]
            )

        # If concatenation bit is set, pad after payload to 4-byte boundary
        # Padding is NOT included in payload size
        if self.c == 1: 
            pad_len = pad_len_to_4_bytes(payload_len)
            pkt += b"\x00" * pad_len
        return pkt
    
    
    

class ECPRI_IQ_DATA(Packet):
    name = "ECPRI_IQ_DATA_MSG",

    fields_desc = [
        ShortField("PC_ID", 0), # How to allocate this value is vendor-specific
        ShortField("SEQ_ID", 0),
        StrLenField("iq_data", b"", length_from = lambda pkt: (pkt.underlayer.payload_size - 4), max_length= 2**16-1),
        #IQ DATA, this has to be a variable length field
        # Refer to section 3.2.4.1 of eCPRI v2.0 specifications
    ]

# Bind layers of ECPRI to chosen transport network protocol
# In this version, ECPRI is bound to Ethernet
bind_layers(Ether, ECPRI, type=ECPRI_ETHERTYPE) # Bind ECPRI layer to Ethernet layer wtih Ethertype 0xAEFE
bind_layers(ECPRI, ECPRI_IQ_DATA, msg_type=0)