from tkinter import *
from CommunicationLayer.client_communication import Client

comm = Client()

fenetre = Tk()
fenetre.geometry('800x600')
titre = Label(fenetre, text="SAVANNA")
server_search = Label(fenetre, text="Recherche du serveur")
server_lost_connection = Label(fenetre, text="Le serveur ne répond pas")
nickname = Label(fenetre, text="description")
nickname_entry = Entry(fenetre, width=50)
bouton = Button(fenetre, text="OK")


def discovered():
    server_search.place_forget()

    titre.place(anchor=CENTER, relx=0.5, rely=0.3)
    nickname.place(anchor=CENTER, relx=0.5, rely=0.5)
    nickname_entry.place(anchor=CENTER, relx=0.5, rely=0.7)
    bouton.place(anchor=CENTER, relx=0.8, rely=0.7)


def discover():
    comm('discovery')

    titre.place(anchor=CENTER, relx=0.5, rely=0.4)
    server_search.place(anchor=CENTER, relx=0.5, rely=0.6)


def no_response():
    titre.place(anchor=CENTER, relx=0.5, rely=0.4)
    server_lost_connection.place(anchor=CENTER, relx=0.5, rely=0.6)


comm.bind_hook('successful_discovery', discovered)
comm.bind_hook('no_response', no_response)

discover()

fenetre.mainloop()
comm.close_session()
