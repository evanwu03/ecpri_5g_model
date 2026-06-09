# Author: Evan Wu
# Date of Revision: 6/9/2026

from scapy.all import Packet, BitField, ByteEnumField, ShortField, Ether, bind_layers


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



class ECPRI(Packet):
    name = "ECPRI"

    # ECPRI follows Big-endian ordering (MSB --> LSB)
    fields_desc = [
        BitField("protocol_revision", 1, 4),
        BitField("reserved", 0, 3), 
        BitField("c", 0, 1), #  Concatenation indicator
        ByteEnumField("msg_type", 0, ECPRI_MSG_TYPES), 
        ShortField("payload_size", 0) # max payload size is 2^16-1 bytes 
    ]



class ECPRI_IQ_DATA(Packet):
    name = "ECPRI_IQ_DATA_MSG",

    fields_desc = [
        ShortField("PC_ID", 0), # How to allocate this value is vendor-specific
        ShortField("SEQ_ID", 0),
        #IQ DATA, this has to be a variable length field
        # Refer to section 3.2.4.1 of eCPRI v2.0 specifications
    ]

bind_layers(Ether, ECPRI, type=ECPRI_ETHERTYPE) # Bind ECPRI layer to Ethernet layer wtih Ethertype 0xAEFE
bind_layers(ECPRI, ECPRI_IQ_DATA, msg_type=0)