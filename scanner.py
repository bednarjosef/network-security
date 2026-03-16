import os

from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap
from scapy.packet import Packet

from monitor_mode import monitor_mode
from channel import channel_hopper

# probably shouldn't be global
networks = {}

def process_data_frame(packet):
    to_ds = packet.FCfield & 0x01
    from_ds = (packet.FCfield & 0x02) >> 1
    
    mac1, mac2 = packet.addr1, packet.addr2
    if not mac1 or not mac2: return
    
    bssid, client = None, None
    if to_ds == 0 and from_ds == 1: bssid, client = mac2, mac1
    elif to_ds == 1 and from_ds == 0: bssid, client = mac1, mac2
    
    if bssid in networks and client:
        if client != 'ff:ff:ff:ff:ff:ff' and not (int(client.split(':')[0], 16) & 1):
            networks[bssid]['clients'].add(client)


def is_packet_dot11(packet: Packet):
    return packet.haslayer(Dot11Beacon)

def get_bssid(packet: Packet):
    return packet[Dot11].addr3

def get_rssi(packet: Packet):
    rssi = -100

    # todo: wtf
    if packet.haslayer(RadioTap) and hasattr(packet[RadioTap], 'dBm_AntSignal') and packet[RadioTap].dBm_AntSignal is not None:
        rssi = int(packet[RadioTap].dBm_AntSignal)

    return rssi

def parse_crypto(crypto):
    simplified = set()
    
    for c in crypto:
        if c.startswith('WPA3-transition'):
            simplified.update(['WPA2', 'WPA3'])
        else:
            base_protocol = c.split('/')[0]
            simplified.add(base_protocol)
            
    order = {'OPN': 0, 'WEP': 1, 'WPA': 2, 'WPA2': 3, 'WPA3': 4}
    sorted_crypto = sorted(list(simplified), key=lambda x: order.get(x, 99))
    
    return '/'.join(sorted_crypto)

def clean_ssid(raw_ssid):
    ssid = ''.join(c for c in raw_ssid if c.isprintable()).strip()
    if not ssid:
        ssid = '<Hidden>'
    return ssid

def packet_handler(packet: Packet):
    if packet.type == 2:
        process_data_frame(packet)
        return

    if not is_packet_dot11(packet):
        return

    bssid = get_bssid(packet)
    if bssid in networks:
        return
    
    stats = packet[Dot11Beacon].network_stats()

    
    ssid = clean_ssid(stats['ssid'])
    channel = stats['channel']
    rates = stats['rates']
    crypto = parse_crypto(stats['crypto'])
    rssi = get_rssi(packet)

    networks[bssid] = {
        'ssid': ssid, 
        'pwr': rssi, 
        'channel': channel, 
        'crypto': crypto, 
        'clients': set()
    }

    # TODO: print also row number i.e. 1.-100.
    print(f'{bssid:<17} | {rssi:<4} | {str(channel):<3} | {crypto:<10} | {ssid[:25]}')


def get_lists():
    networks_list = []
    clients_list = []

    for bssid, info in networks.items():
        networks_list.append({
            'bssid': bssid,
            'ssid': info['ssid'],
            'pwr': info['pwr'],
            'channel': info['channel'],
            'crypto': info['crypto'],
            'client_count': len(info.get('clients', set()))
        })

        for client_mac in info.get('clients', set()):
            clients_list.append({
                'client_mac': client_mac,
                'ssid': info['ssid'],
                'bssid': bssid,
                'channel': info['channel'],
                'crypto': info['crypto']
            })

    # sort networks by signal and clients by ssid alphabetically
    networks_list = sorted(networks_list, key=lambda x: x['pwr'], reverse=True)
    clients_list = sorted(clients_list, key=lambda x: x['ssid'])

    return networks_list, clients_list


def run_scanner(interface):
    networks.clear()

    with monitor_mode(interface) as interface:
        with channel_hopper(interface, delay=0.5):
            print(f'\n({interface}) Scanning for networks... (CTRL+C to stop)\n')
            print(f'{'BSSID':<17} | {'PWR':<4} | {'CH':<3} | {'ENCRYPTION':<10} | {'SSID'}')
            print('-' * 65)

            try:
                sniff(iface=interface, prn=packet_handler, store=False)
            except KeyboardInterrupt:
                pass

    return get_lists()
