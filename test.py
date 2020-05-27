from tkinter import *
from CommunicationLayer.client_communication import Client

comm = Client(verbose=True)


def discovered():
    server_search.place_forget()

    titre.place(anchor=CENTER, relx=0.5, rely=0.3)
    nickname.place(anchor=CENTER, relx=0.5, rely=0.5)
    nickname_entry.place(anchor=CENTER, relx=0.5, rely=0.6)
    bouton.place(anchor=CENTER, relx=0.8, rely=0.6)


def discover():
    comm('discovery')

    titre.place(anchor=CENTER, relx=0.5, rely=0.4)
    server_search.place(anchor=CENTER, relx=0.5, rely=0.6)


def no_response():
    titre.place(anchor=CENTER, relx=0.5, rely=0.4)
    server_lost_connection.place(anchor=CENTER, relx=0.5, rely=0.6)


def propose_request():
    name = nickname_entry.get()
    nickname_entry.delete(0, 'end')
    comm('request', nickname=name)


def on_modify_request():
    nickname_wrong.place(anchor=CENTER, relx=0.5, rely=0.7)


def channel_choice():
    global channels_list

    nickname.place_forget()
    nickname_entry.place_forget()
    bouton.place_forget()
    nickname_wrong.place_forget()
    nickname_entry.delete(0, 'end')

    titre.place_forget()
    titre.pack(side=TOP)

    chans = comm.available_convs
    for i in chans:
        channels_list[i] = Button(fenetre, text=chans[i], command=lambda c=i: join_chan_id(c))
        channels_list[i].pack(side=TOP)


def join_chan_id(cid):
    comm('join_channel', cid=cid)


def main_frame():
    titre.pack_forget()

    for i in channels_list:
        channels_list[i].pack_forget()

    frametop.pack(side=TOP)
    titre_salon.config(text=f"SAVANNA : {comm.current_conv.name}")

    frameconv.pack(side=TOP)
    framebottom.pack(side=BOTTOM)


def send_message():
    comm("send_message", message=message_entry.get())
    message_entry.delete(0, 'end')


def on_message():
    global messages

    message = comm.current_conv_messages[-1]
    sender_name = comm.current_conv.members[str(message['sender_id'])]

    text = f"{sender_name} : {message['content']}"

    t = Label(frameconv, text=text)
    t.pack(side=TOP)
    messages.append(t)


fenetre = Tk()
fenetre.geometry('800x600')
titre = Label(fenetre, text="SAVANNA")
server_search = Label(fenetre, text="Recherche du serveur")
server_lost_connection = Label(fenetre, text="Le serveur ne répond pas")
nickname = Label(fenetre, text="Entrez votre nom d'utilisateur")
nickname_entry = Entry(fenetre, width=50)
nickname_wrong = Label(fenetre, text="Votre nom d'utilisateur n'est pas valide ou est déjà pris")
bouton = Button(fenetre, text="OK", command=propose_request)

# Main frame
frametop = Frame(fenetre, bg="grey", borderwidth=2, relief=GROOVE, height=20, width=800)
titre_salon = Label(frametop, text="Titre")
titre_salon.pack()

frameconv = Frame(fenetre, bg="dark grey", borderwidth=2, relief=GROOVE, height=540, width=800)
frameconv.pack_propagate(0)

framebottom = Frame(fenetre, bg="dark grey", borderwidth=2, relief=GROOVE, height=30, width=800)
framebottom.pack_propagate(0)
message_entry = Entry(framebottom, width=80)
message_entry.pack(side=LEFT)
Button(framebottom, text="Envoyer", command=send_message).pack(side=LEFT)
Button(framebottom, text="Quitter le salon").pack(side=RIGHT)

channels_list = {}
messages = []

comm.bind_hook('successful_discovery', discovered)
comm.bind_hook('no_response', no_response)
comm.bind_hook('modify_request', on_modify_request)
comm.bind_hook("successful_request", lambda: None)
comm.bind_hook("init_channels_list", channel_choice)
comm.bind_hook("connected", main_frame)
comm.bind_hook("message", on_message)

discover()

fenetre.mainloop()
comm.close_session()