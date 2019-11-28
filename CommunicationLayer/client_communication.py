from scapy.all import *
from scapy.layers.inet import UDP, IP
from .messaging_class import MessagingBase
from time import sleep


class Client(MessagingBase):
    # L'ID est défini à -1 dans le init, puis à un nombre positif ou nul lors de la réponse du serveur
    uid = None

    # Les conversations sont sous la forme [conv1_id, conv2_id, ...]
    convs = None

    server_ip = None

    sniffer = None

    hooks = None

    def wait_for(self, secs, cond, final_raise):
        for _ in range(secs):
            if self.answers[cond] is True:
                break
            sleep(1)

        if not self.answers[cond]:
            if type(final_raise) is Exception:
                raise final_raise
            elif callable(final_raise):
                final_raise()

    def bind_hook(self, name, func):
        if name not in self.hooks.keys():
            return

        self.hooks[name] = func

    def __init__(self, verbose=False):
        self.bind_layers_to_protocol()

        # Init
        self.uid = -1
        self.convs = []

        self.answers = {
            'discovery': False,
            'request': False
        }

        self.hooks = {
            'server_failure': None
        }

        self.verbose = verbose

        self.handling_functions = {
            1: lambda pkt, s: self.connexion_process_handler(pkt, s)
        }

    def __call__(self):
        # On teste d'abord si un hook n'a pas été défini
        if None in self.hooks.values():
            raise Exception("A hook has not been given")

        # On définit le sniffer
        self.sniffer = AsyncSniffer(prn=self.test_concern, filter="udp port 65012", store=False)
        self.sniffer.start()

        if self.verbose:
            print("sending discovery packet")

        # On envoie la discovery et on attend
        self.build_and_send_packet('255.255.255.255', 'UDP', 'discovery')
        self.wait_for(10, 'discovery', self.hooks['server_failure'])

        # On définit la requête en demandant le pseudo du client
        self.nickname = str(input("Your nickname: "))
        self.build_and_send_packet(self.server_ip, 'UDP', 'request', payload=self.nickname)
        self.wait_for(10, 'request', self.hooks['server_failure'])

    def connexion_process_handler(self, pkt, subtype):
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

            self.uid = pkt[self.MessagingProtocol].uid
            print(f"Connected with UID {self.uid}")
        elif subtype == 4:
            # On reçoit une Modify, le pseudo est déjà pris par quelqu'un
            raise NotImplementedError

    def close_session(self):
        if self.uid != -1 and self.nickname and self.server_ip:
            self.build_and_send_packet(self.server_ip, 'UDP', 'terminate', uid=self.uid)
        return
