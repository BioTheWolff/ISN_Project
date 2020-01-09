from scapy.all import *
from scapy.layers.inet import IP
from .messaging_class import MessagingBase
import threading
from time import sleep
import json
from typing import Optional


class Client(MessagingBase):
    # L'ID est défini à -1 dans le init, puis à un nombre positif ou nul lors de la réponse du serveur
    uid = None
    tid = None
    nickname = None

    # Les conversations sont sous la forme [conv1_id, conv2_id, ...]
    convs = None
    available_convs = None

    server_ip = None
    sniffer = None

    def raise_or_call(self, hook) -> None:
        if type(hook) is Exception:
            self.close_session()
            raise hook
        elif callable(hook):
            hook()
        else:
            self.close_session()
            raise Exception("Hook not callable nor raisable.")

    def wait_for(self, secs: int, cond: str, final_raise) -> None:
        for i in range(secs):
            if self.answers[cond]:
                break
            sleep(1)

        if not self.answers[cond]:
            self.raise_or_call(final_raise)
        else:
            self.raise_or_call(self.hooks[f"successful_{cond}"])

    #
    # DUNDERS
    #
    def __init__(self, verbose=False) -> None:
        self.bind_layers_to_protocol()

        self.broadcast_addr = self.resolve_broadcast_address()

        # Init
        self.uid = -1
        self.tid = -1
        self.convs = {}
        self.available_convs = {}
        self.server_ip = ''
        self.nickname = ''

        self.answers = {
            'discovery': False,
            'request': False,
            'overview': False
        }
        self.hooks = {
            'no_response': None,

            'successful_discovery': None,
            'successful_request': None,

            'init_channels_list': None,

            'client_connected': None,
            'client_departed': None,
            'channel_created': None,
            'channel_deleted': None,
            'message': None
        }

        self.verbose = verbose

        self.handling_functions = {
            1: lambda pkt, s: self.handler_connection_process(pkt, s),
            2: lambda pkt, s: self.handler_channel_events(pkt, s),
            4: lambda pkt, s: self.handler_data_transmission(pkt, s)
        }

        # On définit le sniffer
        self.sniffer = AsyncSniffer(prn=self.test_concern, filter="udp port 65012", store=False)
        self.sniffer.start()

    def __call__(self, action, daemon=True, **kwargs) -> None:
        # On teste d'abord si un hook n'a pas été défini
        if None in self.hooks.values():
            pass
            # raise Exception("A hook has not been given")

        # On définit les arguments requis pour chaque action
        arguments = {
            'discovery': None,
            'terminate': None,
            'request_available_channels': None,

            'request': ['nickname'],
            'join_channel': ['cid']
        }

        # On vérifie que l'action existe bien
        if action not in arguments.keys():
            raise Exception("Action not recognised")

        params = arguments[action]

        if params:
            # Si il y a des paramètres à passer
            # On teste alors si chaque paramètre requis est présent dans ceux passés
            for param in params:
                if param not in kwargs:
                    raise Exception(f"Missing parameter {param} for action {action}")

            thread = threading.Thread(target=Client.__dict__[f"action_{action}"],
                                      args=(self, *[kwargs[i] for i in params]),
                                      daemon=daemon)
        else:
            # Si l'action peut être appelée sans passer de paramètres
            thread = threading.Thread(target=Client.__dict__[f"action_{action}"],
                                      args=(self,),
                                      daemon=daemon)

        thread.start()

    #
    # ACTIONS
    #
    def action_discovery(self) -> None:
        if self.verbose:
            print("sending discovery packet")

        # On envoie la discovery et on attend
        self.build_and_send_packet(self.broadcast_addr, 'discovery')

        self.wait_for(10, 'discovery', self.hooks['no_response'])

    def action_request(self, nickname: str) -> Optional[bool]:

        if not nickname:
            return False

        # On définit la requête en demandant le pseudo du client
        self.nickname = nickname
        self.build_and_send_packet(self.server_ip, 'request', uid=self.tid, payload=self.nickname)

        self.wait_for(10, 'request', self.hooks['no_response'])

    def action_terminate(self) -> None:
        if self.uid != -1 and self.nickname and self.server_ip:
            # Terminate packet
            self.build_and_send_packet(self.server_ip, 'terminate', uid=self.uid)

            # Variables à redéfinir comme avant la connexion
            self.uid = -1
            self.nickname = ''
            self.server_ip = ''
            self.convs = []
            self.answers = {
                'discovery': False,
                'request': False
            }

    def action_request_available_channels(self) -> None:
        self.build_and_send_packet(self.server_ip, 'overview', uid=self.uid)

    def action_join_channel(self, cid: int) -> None:
        self.build_and_send_packet(self.server_ip, 'connect', cid=cid, uid=self.uid)

    #
    # HANDLERS
    #
    def handler_connection_process(self, pkt: Packet, subtype: int) -> Optional[NotImplementedError]:
        """

        :param pkt: Paquet reçu
        :param subtype: Sous-type du processus de discovery
        :return: None
        """

        if self.uid != -1:
            return

        ip_dst = pkt[IP].src

        if subtype == 1:
            # On a obtenu une offer du server, on change la variable pour que le client
            # ne stoppe pas le timeout à 10 secondes
            self.answers['discovery'] = True
            self.server_ip = ip_dst
            self.tid = int(self.bin_to_str(pkt[self.MessagingProtocol].load))
        elif subtype == 3:
            # Unicité de la transmission par vérification de l'identifiant temporaire
            if int(self.bin_to_str(pkt[self.MessagingProtocol].load)) != self.tid:
                return

            # On a un ACK du serveur, le pseudo est accepté, on stocke notre UID
            self.answers['request'] = True
            self.uid = pkt[self.MessagingProtocol].uid

            self.__call__('request_available_channels')

        elif subtype == 4:
            # On reçoit une Modify, le pseudo est déjà pris par quelqu'un
            raise NotImplementedError

    def handler_channel_events(self, pkt: Packet, subtype: int) -> None:
        uid = pkt[self.MessagingProtocol].uid

        if self.uid != uid:
            return

        if subtype == 2:
            # Member joined
            cid = pkt[self.MessagingProtocol].cid
            loaded_pkt_load = json.loads(self.bin_to_str(pkt[self.MessagingProtocol].load))

            channel = self.convs[cid]
            channel.add_member(str(loaded_pkt_load['id']), loaded_pkt_load['username'])

        elif subtype == 3:
            # Member left
            cid = pkt[self.MessagingProtocol].cid
            pkt_load = self.bin_to_str(pkt[self.MessagingProtocol].load)

            channel = self.convs[cid]
            channel.remove_member(str(pkt_load))

    def handler_data_transmission(self, pkt: Packet, subtype: int) -> None:
        uid = pkt[self.MessagingProtocol].uid

        if self.uid != uid:
            return

        if subtype < 3:
            return

        packet_load = pkt[self.MessagingProtocol].load

        if subtype == 3:
            if not self.answers['overview']:
                self.available_convs = json.loads(self.bin_to_str(packet_load))
                self.raise_or_call(self.hooks['init_channels_list'])
                self.answers['overview'] = True
        elif subtype == 4:
            pkt_cid = pkt[self.MessagingProtocol].cid
            load = self.bin_to_str(pkt[self.MessagingProtocol].load)
            load = json.loads(load)

            name = self.available_convs[str(pkt_cid)]
            channel = self.Channel(pkt_cid, name)

            channel.update_cipher(load['ciphered'])
            channel.update_members(load['members'])

            self.convs[pkt_cid] = channel

    #
    # ALIASES
    #
    def close_session(self) -> None:
        self.__call__('terminate', daemon=False)
