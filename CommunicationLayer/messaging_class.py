from scapy.all import *
from scapy.layers.inet import UDP, IP, TCP
import socket as so


class MessagingBase:
    ip = so.gethostbyname(so.gethostname())
    packet_types = {
        # Se calque sur le DHCP discovery process
        10: "discovery",
        11: "offer",
        12: "request",
        13: "R_ACK",
        14: "R_MOD",
        15: "terminate",

        # Events
        20: "new_user",
        21: "new_channel",
        22: "user_left_channel",
        23: "user_joined_channel",

        # Client-related
        30: "update",
        31: "U_ACK",
        32: "U_MOD",

        # Data transmission
        33: "download",
        34: "response",

        # Messages
        40: "message"
    }

    handling_functions = None
    verbose = None

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
                             20: "new_user",
                             21: "new_channel",
                             22: "user_left_channel",
                             23: "user_joined_channel",

                             # Client-related
                             30: "update",
                             31: "U_ACK",
                             32: "U_DNY",

                             # Data transmission
                             33: "download",
                             34: "response",

                             # Messages
                             40: "message"
                         }),
            IntField("uid", 0),  # User id
            IntField("cid", 0),  # Conv id
            StrField("load", "")
        ]

    def build_and_send_packet(self, ip_dst, transport_type, mp_type, payload='', uid=0, tsp_flags=None):
        """

        :param ip_dst: l'IP du destinataire du paquet
        :param transport_type: Le type de transport, soit UDP (rapidité) soit TCP (connexion de confiance)
        :param mp_type: Raccourci de MessagingProtocol type, soit le type de paquet à envoyer
        :param payload: Le payload éventuel du paquet MessagingProtocol
        :param uid: L'identifiant client
        :param tsp_flags: Les flags éventuels du paquet TCP
        :return:
        """

        if transport_type not in ['UDP', 'TCP']:
            raise Exception('Le type de paquet de la couche de transport doit être TCP ou UDP.')

        ip_pkt = IP(src=self.ip, dst=ip_dst)

        if transport_type == 'TCP':
            tsp_pkt = TCP(sport=65012, dport=65012, flags=tsp_flags)
        else:
            tsp_pkt = UDP(sport=65012, dport=65012)

        mp_pkt = self.MessagingProtocol(type=mp_type, load=payload, uid=uid)

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
        if IP in pkt and UDP in pkt and pkt[UDP].sport == 65012 and pkt[UDP].dport == 65012 \
                and self.MessagingProtocol in pkt:
            # The recieved packet concerns us
            packet_load = pkt[self.MessagingProtocol].load
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
        bind_layers(UDP, self.MessagingProtocol, sport=65012)
        bind_layers(UDP, self.MessagingProtocol, dport=65012)

        # Bind TCP
        # Les paquets TCP seront utilisés pour toutes transmissions ultérieures au discovery
        bind_layers(TCP, self.MessagingProtocol, sport=65012)
        bind_layers(TCP, self.MessagingProtocol, dport=65012)
