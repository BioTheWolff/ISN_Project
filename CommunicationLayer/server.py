from scapy.all import *
from scapy.layers.inet import IP
from .messaging_class import MessagingBase


class Server(MessagingBase):
    # Les conversations sont sous la forme conv_id => {clientX_id, clientY_id, ...}
    # L'identifiant de chaque client est contenu dans la conversation
    convs = None

    # Les clients sont sous la forme id => IP
    clients = None

    nicknames = None
    last_uid = None

    def __init__(self, verbose=None):
        self.bind_layers_to_protocol()

        # Init
        self.convs = {}
        self.clients = {}
        self.verbose = verbose

        self.nicknames = {}
        self.last_uid = 1

        self.handling_functions = {
            # Discovery type
            1: lambda pkt, s: self.connexion_process_handler(pkt, s),
            9: lambda *_: print(self.clients, '\n', self.nicknames)
        }

    def __call__(self):
        if self.verbose:
            print("starting to listen")

        sniff(prn=self.test_concern, filter="udp port 65012", store=False)

    def connexion_process_handler(self, pkt, subtype):
        """

        :param pkt: Paquet reçu
        :param subtype: Sous-type du processus de discovery
        :return: None
        """

        # L'IP du destinataire de la réponse est l'IP de la source du paquet
        ip_dst = pkt[IP].src

        if subtype == 0:
            # On a Discovery du client, on lui renvoie une Offer
            self.build_and_send_packet('255.255.255.255', 'UDP', 11)
        elif subtype == 2:
            # On a une Request du client
            # Réponses possibles: Acknowledge ou Modify

            # on prend le pseudo demandé
            nickname = str(pkt[self.MessagingProtocol].load)[2:-1]

            if nickname in self.nicknames.values():
                # Le pseudo existe déjà, on renvoie un Modify
                self.build_and_send_packet(ip_dst, 'UDP', 'R_MOD')
                return
            else:
                # On crée le client et on l'enregistre
                self.clients[self.last_uid] = ip_dst
                self.nicknames[self.last_uid] = nickname

                self.build_and_send_packet(ip_dst, 'UDP', 'R_ACK', uid=self.last_uid)

                self.last_uid += 1

                print(self.clients, '\n', self.nicknames)
        elif subtype == 5:
            # On reçoit un Terminate (le client ferme la connexion)
            uid = pkt[self.MessagingProtocol].uid

            self.clients[uid] = None
            self.nicknames[uid] = None

            print(self.clients, '\n', self.nicknames)
