from CommunicationLayer.client_communication import Client
from tkinter import *


def test():
    status.config(text="No response from the server")
    request_button.pack_forget()
    channels_frame.pack_forget()
    members_frame.pack_forget()
    discovery_button.pack()



def discover():
    status.config(text="Discovering")
    comm_layer('discovery')


def discovered():
    status.config(text="Server found")
    request_button.pack()
    discovery_button.pack_forget()


def request():
    status.config(text="Trying to connect")
    comm_layer('request', nickname='BioWolf')


def requested():
    channels_frame.pack(side=LEFT)
    members_frame.pack(side=RIGHT)

    status.config(text=f"Connected with name {comm_layer.nickname} (UID: {comm_layer.uid})")
    request_button.pack_forget()


def init_render_channels():
    chans = comm_layer.available_convs
    for i in chans:
        channels_list[i] = Label(channels_frame, text=chans[i])
        channels_list[i].pack()


def terminate():
    comm_layer.close_session()
    status.config(text="Waiting...")
    terminate_button.pack_forget()
    discovery_button.pack()


win = Tk()
status = Label(text="Waiting...")

discovery_button = Button(win, text='Discovery', command=discover)
request_button = Button(win, text="Request for 'BioWolf'", command=request)
terminate_button = Button(win, text="Close session", command=terminate)

channels_frame = Frame(bg='grey', height=600)
channels_list = {}

members_frame = Frame(bg='grey', height=600)

comm_layer = Client()
comm_layer.bind_hook('no_response', test)
comm_layer.bind_hook('successful_discovery', discovered)
comm_layer.bind_hook('successful_request', requested)
comm_layer.bind_hook('init_channels_list', init_render_channels)

status.pack()
discovery_button.pack()

win.mainloop()

comm_layer.close_session()
