import os

from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap
from scapy.packet import Packet

from monitor_mode import monitor_mode
from channel import channel_hopper, set_channel

# TODO: show list of scanned clients

# probably shouldn't be global
networks = {}
clients = {}

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

def network_scan_packet_handler(packet: Packet):
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
        # 'clients': set()
    }

    row_num = len(networks)
    print(f'{row_num:<3} | {bssid:<17} | {rssi:<4} | {channel:<3} | {crypto:<10} | {ssid[:25]}')


def client_scan_packet_handler(packet: Packet, target_bssid: str):
    # We only care about Data frames (Type 2) which include regular data and Null Keep-Alives
    if packet.type == 2:
        to_ds = packet.FCfield & 0x01
        from_ds = (packet.FCfield & 0x02) >> 1
        
        mac1, mac2 = packet.addr1, packet.addr2
        if not mac1 or not mac2: 
            return
        
        bssid, client = None, None
        
        # Determine which MAC is the AP and which is the Client
        if to_ds == 0 and from_ds == 1: 
            bssid, client = mac2, mac1
        elif to_ds == 1 and from_ds == 0: 
            bssid, client = mac1, mac2
        
        # If the packet belongs to our target network, and we found a client MAC
        if bssid == target_bssid and client:
            # Ignore broadcast and multicast MACs
            if client != 'ff:ff:ff:ff:ff:ff' and not (int(client.split(':')[0], 16) & 1):
                
                # If we haven't seen this client yet, add them and print!
                if client not in clients:
                    rssi = get_rssi(packet)
                    clients[client] = {'pwr': rssi}
                    
                    row_num = len(clients)
                    print(f'{row_num:<3} | {client:<17} | {rssi:<4}')
                    

def get_networks_list():
    networks_list = []

    for bssid, info in networks.items():
        networks_list.append({
            'bssid': bssid,
            'ssid': info['ssid'],
            'pwr': info['pwr'],
            'channel': info['channel'],
            'crypto': info['crypto'],
        })

    networks_list = sorted(networks_list, key=lambda x: x['pwr'], reverse=True)
    return networks_list

def get_clients_list(target_bssid, target_channel, target_ssid, target_crypto):
    clients_list = []
    
    for client_mac, info in clients.items():
        clients_list.append({
            'mac': client_mac,
            'bssid': target_bssid,
            'ssid': target_ssid,
            'pwr': info['pwr'],
            'channel': target_channel,
            'crypto': target_crypto
        })

    clients_list = sorted(clients_list, key=lambda x: x['pwr'], reverse=True)
    return clients_list


def run_network_scanner(interface):
    networks.clear()

    with monitor_mode(interface) as interface:
        with channel_hopper(interface, delay=0.5):
            print(f'\n({interface}) Scanning for networks... (CTRL+C to stop)\n')
            print(f'{'#':<3} | {'BSSID':<17} | {'PWR':<4} | {'CH':<3} | {'ENCRYPTION':<10} | {'SSID'}')
            print('-' * 71)

            try:
                sniff(iface=interface, prn=network_scan_packet_handler, store=False)
            except KeyboardInterrupt:
                pass

    return get_networks_list()


def run_client_scanner(interface, bssid, channel):
    clients.clear()

    # should probably just pass these as function params from main.py
    target_net = networks.get(bssid, {})
    ssid = target_net.get('ssid', '<Unknown>')
    crypto = target_net.get('crypto', '?')

    with monitor_mode(interface) as interface:
        set_channel(interface, channel)
        print(f'\n({interface}) Scanning for clients on network {ssid}... (CTRL+C to stop)\n')
        print(f'{'#':<3} | {'CLIENT MAC':<17} | {'PWR':<4}')
        print('-' * 33)

        try:
            sniff(iface=interface, prn=lambda p: client_scan_packet_handler(p, bssid), store=False)
        except KeyboardInterrupt:
            pass
    
    return get_clients_list(bssid, channel, ssid, crypto)
