# Set log level to benefit from Scapy warnings
import logging

logger = logging.getLogger("scapy")
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())

from scapy.all import *
from scapy.layers.inet import UDP, IP

packet_types = {
        # Se calque sur le DHCP discovery process
        10: "discovery",
        11: "offer",
        12: "request",
        13: "R_ACK",
        14: "R_MOD",
        15: "terminate",

        # Events
        20: "user_new",
        21: "channel_new",
        22: "user_left",
        23: "user_joined",

        # Client-related
        30: "update",
        31: "U_ACK",
        32: "U_DNY",

        # Data transmission
        40: "download",
        41: "response",

        # Messages
        50: "message"
    }


class MessagingProtocol(Packet):
    name = "MessagingProtocol "
    fields_desc = [
        IntEnumField("type", 10,
                     {
                         # Se calque sur le DHCP discovery process
                         10: "discovery",
                         11: "offer",
                         12: "request",
                         13: "R_ACK",
                         14: "R_MOD",
                         15: "terminate",

                         # Events
                         20: "user_new",
                         21: "channel_new",
                         22: "user_left",
                         23: "user_joined",

                         # Client-related
                         30: "update",
                         31: "U_ACK",
                         32: "U_DNY",

                         # Data transmission
                         40: "download",
                         41: "response",

                         # Messages
                         50: "message"
                     }),
        IntField("uid", 0),  # User id
        IntField("cid", 0),  # Conv id
        StrField("load", "")
    ]


bind_layers(UDP, MessagingProtocol, sport=65012)
bind_layers(UDP, MessagingProtocol, dport=65012)


def sum_type(pkt):
    print(pkt.summary())

    if MessagingProtocol not in pkt:
        return

    t = packet_types[pkt[MessagingProtocol].type]
    l = pkt[MessagingProtocol].load
    u = pkt[MessagingProtocol].uid
    c = pkt[MessagingProtocol].cid

    print(f"    type : {t}")
    print(f"  {'>' if l != b'' else ' '} load : {l}")
    print(f"  {'>' if u != 0 else ' '}  uid : {u}")
    print(f"  {'>' if c != 0 else ' '}  cid : {c}")
    print()


def xshow():
    sniff(prn=lambda x: x.show(), filter="udp port 65012", store=False)


def xsum(port=65012):
    sniff(prn=sum_type, filter=f"udp port {port}", store=False)


def netw(dst=None):
    return IP(dst=dst) / UDP(sport=65012, dport=65012)


def mp(type_, load='', u=0):
    return MessagingProtocol(type=type_, load=load, uid=u)


def dpkt():
    send(netw() / mp(99))


if __name__ == "__main__":
    interact(mydict=globals(), mybanner="MessagingProtocol Add-on v1.0")
