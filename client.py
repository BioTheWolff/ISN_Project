from CommunicationLayer.client_communication import Client
from tkinter import *
import asyncio as a


def test():
    status.config(text="No response from the server")


def discover():
    status.config(text="Discovering")
    instance('discovery')


def discovered():
    status.config(text="Server found")
    request_button.pack()
    discovery_button.pack_forget()


def request():
    status.config(text="Trying to connect")
    instance('request', nickname='BioWolf')


def requested():
    status.config(text=f"Connected with name {instance.nickname} (UID: {instance.uid})")
    request_button.pack_forget()
    terminate_button.pack()


def terminate():
    instance.close_session()
    status.config(text="Waiting...")
    terminate_button.pack_forget()
    discovery_button.pack()


win = Tk()
status = Label(text="Waiting...")
discovery_button = Button(win, text='Discovery', command=discover)
request_button = Button(win, text="Request for 'BioWolf'", command=request)
terminate_button = Button(win, text="Close session", command=terminate)
wild_button = Button(win, text="WILD", command=lambda: status.config(text="WIIIIIILD"))

instance = Client()
instance.bind_hook('no_response', test)
instance.bind_hook('successful_discovery', discovered)
instance.bind_hook('successful_request', requested)

status.pack()
discovery_button.pack()
wild_button.pack()

win.mainloop()

instance.close_session()
