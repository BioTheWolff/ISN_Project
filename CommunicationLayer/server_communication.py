from scapy.all import *
from scapy.layers.inet import IP
from .messaging_class import MessagingBase
import json


class Server(MessagingBase):
    # Les conversations sont sous la forme conv_id => {clientX_id, clientY_id, ...}
    # L'identifiant de chaque client est contenu dans la conversation
    convs = None

    # Les clients sont sous la forme id => IP
    clients = None

    nicknames = None
    last_uid = None
    last_cid = None

    #
    # DUNDERS
    #
    def __init__(self, verbose=None):
        self.bind_layers_to_protocol()

        # Init
        self.convs = {
            1: self.Channel(1, 'Test1', 'chan')
        }
        self.clients = {}
        self.verbose = verbose

        self.nicknames = {}
        self.last_uid = 1
        self.last_cid = len(self.convs) + 1

        self.handling_functions = {
            # Discovery type
            1: lambda pkt, s: self.handler_connection_process(pkt, s),
            4: lambda pkt, s: self.handler_data_transmission(pkt, s),

            9: lambda *_: print(self.clients, '\n', self.nicknames)
        }

        self.hooks = {
            'no_response': None,
            'client_connected': None,
            'client_departed': None,
            'channel_created': None,
            'channel_deleted': None,
            'message': None
        }

    def __call__(self):
        if self.verbose:
            print("starting to listen")

        sniff(prn=self.test_concern, filter="udp port 65012", store=False)

    #
    # HANDLERS
    #
    def handler_connection_process(self, pkt, subtype):
        """

        :param pkt: Paquet reçu
        :param subtype: Sous-type du processus de discovery
        :return: None
        """

        # L'IP du destinataire de la réponse est l'IP de la source du paquet
        ip_dst = pkt[IP].src

        if subtype == 0:
            # On a Discovery du client, on lui renvoie une Offer
            self.build_and_send_packet('255.255.255.255', 'offer')
        elif subtype == 2:
            # On a une Request du client
            # Réponses possibles: Acknowledge ou Modify

            # on prend le pseudo demandé
            nickname = self.bin_to_str(pkt[self.MessagingProtocol].load)

            if nickname in self.nicknames.values():
                # Le pseudo existe déjà, on renvoie un Modify
                self.build_and_send_packet(ip_dst, 'R_MOD')
                return
            else:
                # On crée le client et on l'enregistre
                self.clients[self.last_uid] = ip_dst
                self.nicknames[self.last_uid] = nickname

                self.build_and_send_packet(ip_dst, 'R_ACK', uid=self.last_uid)

                self.last_uid += 1
        elif subtype == 5:
            # On reçoit un Terminate (le client ferme la connexion)
            uid = pkt[self.MessagingProtocol].uid

            self.clients[uid] = None
            self.nicknames[uid] = None

    def handler_data_transmission(self, pkt, subtype):
        if subtype != 0:
            return

        ip_dst = pkt[IP].src
        packet_load = pkt[self.MessagingProtocol].load

        if packet_load == b'0':
            final = {}

            for chan_id in self.convs:
                if self.convs[chan_id].type == 'chan':
                    final[chan_id] = self.convs[chan_id].name

            dumped = json.dumps(final)

            self.build_and_send_packet(ip_dst, 'response', payload=dumped)
