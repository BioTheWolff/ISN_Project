from CommunicationLayer.client_communication import Client
from tkinter import *

# Window
win = Tk()
win.geometry("500x500")
win.configure(bg="darkgrey")

# Comm layer init
comm_layer = Client()
# comm_layer(ACTION, **params)
# ACTIONs: 'discovery', 'request' (param: nickname), 'terminate'

state = "disconnected"


# Commands
def main_menu_no_response():
    global state

    if state == "nickname_entry":
        login_label.pack_forget()
        entry.pack_forget()
        login_button.pack_forget()
        username_warning_label.pack_forget()
    elif state == 'main':
        entry.place_forget()

    lost_connection_label.place(anchor=CENTER, relx=0.5, rely=0.4)
    discovery_button.place(anchor=CENTER, relx=0.5, rely=0.6)


def discovered():
    global state
    discovery_button.pack_forget()
    login_label.pack()
    entry.pack()
    login_button.pack()
    state = "nickname_entry"


def on_modify_request():
    username_warning_label.pack()


def main_frame():
    global state

    state = "main"
    entry.place(anchor=CENTER, relx=0.4, rely=0.5)
    send_button.place(anchor=CENTER, relx=0.7, rely=0.5)


def send_message():
    comm_layer("send_message", message=entry.get())
    entry.delete(0, 'end')


login_label = Label(win, text="Ceci est un texte", bg="darkgrey", fg="darkred")
username_warning_label = Label(win, text="Ce pseudonyme n'est pas valable ou déjà pris", bg="darkgrey", fg="darkred")
lost_connection_label = Label(win, text="Le client a perdu la connexion au serveur")

entry = Entry(win, width=50)
send_button = Button(win, command=send_message)

discovery_button = Button(win, text="Chercher un serveur", command=lambda: comm_layer('discovery'))
login_button = Button(win, text="Se connecter", command=comm_layer('request', nickname=entry.get()))

# Hooks binds
comm_layer.bind_hook("no_response", main_menu_no_response)
comm_layer.bind_hook("successful_discovery", discovered)
comm_layer.bind_hook("modify_request", on_modify_request)
comm_layer.bind_hook("successful_request", main_frame)

discovery_button.pack()

win.mainloop()
comm_layer.close_session()
