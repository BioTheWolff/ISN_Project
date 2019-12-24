from scapy.all import *
from scapy.layers.inet import IP
from .messaging_class import MessagingBase
import json


class Server(MessagingBase):
    convs = None

    # Les clients sont sous la forme id => IP
    clients = None
    temporary_ids = None

    usernames = None
    last_uid = None
    last_tid = None
    last_cid = None

    #
    # DUNDERS
    #
    def __init__(self, verbose=None):
        self.bind_layers_to_protocol()

        self.broadcast_addr = self.resolve_broadcast_address()

        # Init
        self.convs = {
            1: self.Channel(1, 'Test1'),
            2: self.Channel(2, 'Test2')
        }
        self.clients = {}
        self.verbose = verbose

        self.usernames = {}
        self.last_uid = 1
        self.last_tid = 1
        self.last_cid = len(self.convs) + 1

        self.handling_functions = {
            # Discovery type
            1: lambda pkt, s: self.handler_connection_process(pkt, s),
            2: lambda *_: None,
            4: lambda pkt, s: self.handler_data_transmission(pkt, s),

            9: lambda *_: print(self.clients, '\n', self.usernames)
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
    # EXECUTERS
    #
    def tell_members_of_channel(self, cid, event_type, load=''):

        members = self.convs[cid].members

        if not members:
            return

        for uid in members:
            ip = members[uid]

            self.build_and_send_packet(ip, event_type, uid=uid, cid=cid, payload=load)

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
            self.build_and_send_packet(ip_dst, 'offer', payload=self.last_tid)
            self.last_tid += 1
        elif subtype == 2:
            # On a une Request du client
            # Réponses possibles: Acknowledge ou Modify

            # on prend le pseudo demandé
            nickname = self.bin_to_str(pkt[self.MessagingProtocol].load)
            temp_id = pkt[self.MessagingProtocol].uid

            if nickname in self.usernames.values():
                # Le pseudo existe déjà, on renvoie un Modify
                self.build_and_send_packet(ip_dst, 'R_MOD', payload=temp_id)
            else:
                # On crée le client et on l'enregistre
                self.clients[self.last_uid] = ip_dst
                self.usernames[self.last_uid] = nickname

                self.build_and_send_packet(ip_dst, 'R_ACK', uid=self.last_uid, payload=temp_id)
                self.last_uid += 1

        elif subtype == 5:
            # On reçoit un Terminate (le client ferme la connexion)
            uid = pkt[self.MessagingProtocol].uid

            if uid not in self.clients:
                return

            self.clients[uid] = None
            self.usernames[uid] = None

            for id_ in self.convs:
                chan = self.convs[id_]
                if chan.members and uid in chan.members:
                    chan.remove_member(uid)

                    self.tell_members_of_channel(id_, 'user_left', load=uid)

    def handler_data_transmission(self, pkt, subtype):
        if subtype == 3:
            return

        ip_dst = pkt[IP].src
        uid_dst = pkt[self.MessagingProtocol].uid

        if subtype == 0:
            # Overview des salons
            final = {}

            for chan_id in self.convs:
                if self.convs[chan_id].type == 'chan':
                    final[chan_id] = self.convs[chan_id].name

            dumped = json.dumps(final)

            self.build_and_send_packet(ip_dst, 'R_overview', uid=uid_dst, payload=dumped)

        elif subtype == 1:
            # Connexion d'un membre à un salon

            pkt_cid = pkt[self.MessagingProtocol].cid
            channel = self.convs[pkt_cid]

            # On prévient les autres membres déjà connectés
            dumped_new_member = json.dumps({'id': uid_dst, 'username': self.usernames[uid_dst]})
            self.tell_members_of_channel(pkt_cid, 'user_joined', load=dumped_new_member)

            # On ajoute le membre au salon
            channel.add_member(uid_dst, ip_dst)

            # On constitue la liste des membres et les détails
            # On doit changer la consitution de la liste car la liste côté serveur est ID => IP
            # et côté client on préfèrera ID => pseudo
            members_list = {uid: self.usernames[uid] for uid in self.usernames}

            details = {'ciphered': channel.ciphered, 'members': members_list}
            dumped_details = json.dumps(details)

            self.build_and_send_packet(ip_dst, 'R_connect', uid=uid_dst, cid=pkt_cid, payload=dumped_details)

