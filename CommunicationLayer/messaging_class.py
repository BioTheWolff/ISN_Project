from scapy.all import *
from scapy.layers.inet import UDP, IP, TCP
import socket as so
from time import time as now_timestamp
import netifaces


class MessagingBase:
    # Classe personnalisée de paquets
    class MessagingProtocol(Packet):
        name = "MessagingProtocol "
        fields_desc = [
            IntEnumField("type", 10,
                         # Le dictionnaire passé ici est le même que packet_types, en effet.
                         # Mais on ne peut pas passer de self reference pour une constante de classe, et les classes
                         # de paquets de Scapy n'acceptent pas de __init__ pour la bonne raison que le paquet ne doit
                         # pas être instancié, donc pris en absolu. D'où la duplication.
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
            IntField("cid", 0),  # Channel id
            StrField("load", "")
        ]

    # Classe des salons
    class Channel:
        id = None
        name = None
        type = None
        members = None
        ciphered = None
        messages = None

        def __init__(self, cid, name, type_, members=None, ciphered=False):
            self.id = cid
            self.name = name
            self.type = type_
            self.members = members
            self.ciphered = ciphered

        def add_member(self, uid, ip):
            self.members[uid] = ip

        def remove_member(self, uid):
            del self.members[uid]

        def log_message(self, msg):
            self.messages[now_timestamp()] = msg

    ip = so.gethostbyname(so.gethostname())
    port = 65012

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

    handling_functions = None
    verbose = None
    hooks = None

    @staticmethod
    def resolve_broadcast_address():
        for _, interface in enumerate(netifaces.interfaces()):
            i = netifaces.ifaddresses(interface)

            if netifaces.AF_INET in i:
                if i[netifaces.AF_INET][0]['addr'] != '127.0.0.1':
                    return i[netifaces.AF_INET][0]['broadcast']

    @staticmethod
    def bin_to_str(x):
        return str(x)[2:-1]

    def bind_hook(self, name, func):
        if name not in self.hooks.keys():
            return

        self.hooks[name] = func

    def build_and_send_packet(self, ip_dst, mp_type, payload='', uid=0, cid=0):
        """

        :param ip_dst: l'IP du destinataire du paquet
        :param mp_type: Raccourci de MessagingProtocol type, soit le type de paquet à envoyer
        :param payload: Le payload éventuel du paquet MessagingProtocol
        :param uid: L'identifiant client
        :param cid: L'identifiant du salon
        :return:
        """

        ip_pkt = IP(src=self.ip, dst=ip_dst)

        tsp_pkt = UDP(sport=self.port, dport=self.port)

        mp_pkt = self.MessagingProtocol(type=mp_type, load=str(payload), uid=int(uid), cid=int(cid))

        final_pkt = ip_pkt / tsp_pkt / mp_pkt

        send(final_pkt, verbose=False)

    def test_concern(self, pkt):
        """
            Cette fonction regarde les couches du paquet pour vérifier qu'il contient bien les choses requises:
            un protocole IP, un protocole UDP ports entrant et sortant numéro 65012, et la classe de paquet
            que nous avons créée un peu plus haut. Si ces tests passent, la fonction va appeler la classe/fonction
            correspondante pour un handling plus approfondi (et découpé en plusieurs fonctions pour la lisibilité)

        :param pkt: Paquet sniffé par Scapy
        :return: Aucun return, on fait un appel de la fonction correspondante au type reçu
        """

        # Packet is of form:
        # <IP  frag=0 proto=udp |<UDP  sport=9559 dport=9559 |<MessagingProtocol |>>>
        if IP in pkt and UDP in pkt and pkt[UDP].sport == self.port and pkt[UDP].dport == self.port \
                and self.MessagingProtocol in pkt:
            # The recieved packet concerns us
            packet_type, packet_subtype = [int(i) for i in str(pkt[self.MessagingProtocol].type)]

            if self.verbose:
                if pkt[self.MessagingProtocol].type in self.packet_types:
                    print(f"found {self.packet_types[pkt[self.MessagingProtocol].type]} from {pkt[IP].src}")
                else:
                    print(f"found debug packet from {pkt[IP].src}")

            # On passe au handler concerné qui saura s'en occuper
            self.handling_functions[packet_type](pkt, packet_subtype)

    def bind_layers_to_protocol(self):
        """
            Bind UDP
            Les paquets UDP sont utilisés pour le discovery process
            Pour le discovery process, se référer à
            https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol#Operation
            Les étapes Discovery (client), Offer (serveur), Request (client) et Acknowledge (serveur)
            se déroulent par UDP, car on préfèrera la rapidité des paquets UDP à la conservation des TCP
        """
        bind_layers(UDP, self.MessagingProtocol, sport=self.port)
        bind_layers(UDP, self.MessagingProtocol, dport=self.port)

        # Bind TCP
        # Les paquets TCP seront utilisés pour toutes transmissions ultérieures au discovery
        bind_layers(TCP, self.MessagingProtocol, sport=self.port)
        bind_layers(TCP, self.MessagingProtocol, dport=self.port)
