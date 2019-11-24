from CommunicationLayer.client_communication import Client


def server_failure():
    print('The server was not found or is not responding in time.')
    exit(1)


instance = Client(verbose=True)
instance(server_failure)
