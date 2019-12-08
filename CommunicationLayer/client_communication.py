from scapy.all import *
from scapy.layers.inet import IP
from .messaging_class import MessagingBase
import threading
from time import sleep
import json


class Client(MessagingBase):
    # L'ID est défini à -1 dans le init, puis à un nombre positif ou nul lors de la réponse du serveur
    uid = None
    nickname = None

    # Les conversations sont sous la forme [conv1_id, conv2_id, ...]
    convs = None
    available_convs = None

    server_ip = None
    sniffer = None

    @staticmethod
    def raise_or_call(hook):
        if type(hook) is Exception:
            raise hook
        elif callable(hook):
            hook()
        else:
            raise Exception("Hook not callable nor raisable.")

    def wait_for(self, secs, cond, final_raise):
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
    def __init__(self, verbose=False):
        self.bind_layers_to_protocol()

        self.broadcast_addr = self.resolve_broadcast_address()

        # Init
        self.uid = -1
        self.convs = {}
        self.available_convs = {}
        self.server_ip = ''
        self.nickname = ''

        self.answers = {
            'discovery': False,
            'request': False
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
            1: lambda pkt, s: self.handler_connection_process(pkt, s)
        }

        # On définit le sniffer
        self.sniffer = AsyncSniffer(prn=self.test_concern, filter="udp port 65012", store=False)
        self.sniffer.start()

    def __call__(self, action, **kwargs):
        # On teste d'abord si un hook n'a pas été défini
        if None in self.hooks.values():
            pass
            # raise Exception("A hook has not been given")

        # On définit les arguments requis pour chaque action
        arguments = {
            'discovery': None,
            'terminate': None,
            'request_available_channels': None,

            'request': ['nickname']
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
                                      daemon=True)
        else:
            # Si l'action peut être appelée sans passer de paramètres
            thread = threading.Thread(target=Client.__dict__[f"action_{action}"],
                                      args=(self,),
                                      daemon=True)

        thread.start()

    #
    # ACTIONS
    #
    def action_discovery(self):
        if self.verbose:
            print("sending discovery packet")

        # On envoie la discovery et on attend
        self.build_and_send_packet(self.broadcast_addr, 'discovery')

        self.wait_for(10, 'discovery', self.hooks['no_response'])

    def action_request(self, nickname):
        if not nickname:
            return False

        # On définit la requête en demandant le pseudo du client
        self.nickname = nickname
        self.build_and_send_packet(self.server_ip, 'request', payload=self.nickname)

        self.wait_for(10, 'request', self.hooks['no_response'])

    def action_terminate(self):
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

    def action_request_available_channels(self):
        self.build_and_send_packet(self.server_ip, 'download', payload=0)

    #
    # HANDLERS
    #
    def handler_connection_process(self, pkt, subtype):
        """

        :param pkt: Paquet reçu
        :param subtype: Sous-type du processus de discovery
        :return: None
        """

        ip_dst = pkt[IP].src

        if subtype == 1:
            # On a obtenu une offer du server, on change la variable pour que le client
            # ne stoppe pas le timeout à 10 secondes
            self.answers['discovery'] = True
            self.server_ip = ip_dst
        elif subtype == 3:
            # On a un ACK du serveur, le pseudo est accepté, on stocke notre UID
            self.answers['request'] = True

            self.__call__('request_available_channels')

            self.uid = pkt[self.MessagingProtocol].uid
        elif subtype == 4:
            # On reçoit une Modify, le pseudo est déjà pris par quelqu'un
            raise NotImplementedError

    def handler_data_transmission(self, pkt, subtype):
        if subtype != 1:
            return

        packet_load = pkt[self.MessagingProtocol].load

        self.available_convs = json.loads(self.bin_to_str(packet_load))
        self.raise_or_call('init_channels_list')

    #
    # ALIASES
    #
    def close_session(self):
        self.__call__('terminate')
