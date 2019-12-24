from CommunicationLayer.client_communication import Client
from tkinter import *


def test():
    status.config(text="No response from the server")
    request_1_button.place_forget()
    request_2_button.place_forget()
    channels_frame.place_forget()
    members_frame.place_forget()
    discovery_button.place(anchor=CENTER, relx=0.5, rely=0.55)


def discover():
    status.config(text="Discovering")
    comm_layer('discovery')


def discovered():
    status.config(text="Server found")
    discovery_button.place_forget()
    request_1_button.place(anchor=CENTER, relx=0.5, rely=0.55)
    request_2_button.place(anchor=CENTER, relx=0.5, rely=0.65)


def request(username):
    status.config(text="Trying to connect")
    comm_layer('request', nickname=username)


def requested():
    request_1_button.place_forget()
    request_2_button.place_forget()
    status.place_forget()

    channels_frame.grid(row=0, column=0)
    members_frame.grid(row=0, column=1)
    status.grid(row=0, column=2)

    status.config(text=f"Connected with name {comm_layer.nickname} (UID: {comm_layer.uid})")


def init_render_channels():
    chans = comm_layer.available_convs
    for i in chans:
        channels_list[i] = Button(channels_frame, text=chans[i], command=lambda: join_chan_id(i))
        channels_list[i].pack()


def join_chan_id(cid):
    comm_layer('join_channel', cid=cid)


def terminate():
    comm_layer.close_session()
    status.config(text="Waiting...")
    terminate_button.pack_forget()
    discovery_button.pack()


win = Tk()
win.geometry('900x600')
win.configure(bg="grey")
status = Label(text="Waiting...", bg='grey', fg='white')

discovery_button = Button(win, text='Discovery', command=discover)
request_1_button = Button(win, text="Request for 'BioWolf'", command=lambda: request('BioWolf'))
request_2_button = Button(win, text="Request for 'Shetland'", command=lambda: request('Shetland'))
terminate_button = Button(win, text="Close session", command=terminate)

channels_frame = Frame(bg='darkgrey', height=600, width=200)
channels_list = {}

members_frame = Frame(bg='darkgrey', height=600, width=200)

comm_layer = Client(verbose=True)
comm_layer.bind_hook('no_response', test)
comm_layer.bind_hook('successful_discovery', discovered)
comm_layer.bind_hook('successful_request', requested)
comm_layer.bind_hook('init_channels_list', init_render_channels)

status.place(anchor=CENTER, relx=0.5, rely=0.45)
discovery_button.place(anchor=CENTER, relx=0.5, rely=0.55)

win.mainloop()

comm_layer.close_session()
