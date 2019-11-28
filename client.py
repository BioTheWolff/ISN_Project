from CommunicationLayer.client_communication import Client


def test():
    print('The server was not found or is not responding in time.')
    exit(1)


instance = Client(verbose=True)

instance.bind_hook('server_failure', test)

instance()

instance.close_session()
