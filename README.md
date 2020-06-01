# ISN Project

Projet de système de messagerie instantané pour le projet ISN BAC 2020.

Le projet est basé sur tkinter pour le frontend et sur scapy pour le backend. Tout a été construit depuis la base même d'un paquet réseau Scapy.

**ATTENTION**: Il faut installer WinPcap pour que le programme fonctionne. Par défaut, windows ne peut transmettre de paquets ou les écouter nativement

Le client communique au serveur par client_communication.py et le serveur (headless) concerne le fichier server_communication.py

Étant très mauvais en tkinter, je me suis concentré sur la partie backend tandis que mes deux camarades travaillent sur la partie frontend.

Comment utiliser:

Il faut lancer dans un terminal le server.py puis lancer client.py (on peut lancer plusieurs clients, tout a été fait pour ça). Sans le serveur allumé, le client ne pourra se connecter.
