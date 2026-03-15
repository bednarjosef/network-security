import subprocess
from contextlib import contextmanager


def get_wifi_interfaces():
    interfaces = []
    result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, check=True)
        
    for line in result.stdout.split('\n'):
        if "Interface" in line:
            interface = line.split()[1]
            interfaces.append(interface)
        
    return interfaces


def get_monitor_interface_name(interface):
    return interface + 'mon'

def get_managed_interface_name(interface):
    if interface.endswith('mon'):
        return interface[:-3]
    return interface


def kill_wifi_processes():
    subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL)


def enter_monitor_mode(interface):
    subprocess.run(['sudo', 'airmon-ng', 'start', interface], stdout=subprocess.DEVNULL)
    return get_monitor_interface_name(interface)


def leave_monitor_mode(interface):
    subprocess.run(['sudo', 'airmon-ng', 'stop', interface], stdout=subprocess.DEVNULL)
    subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'], stdout=subprocess.DEVNULL)
    return get_managed_interface_name(interface)


@contextmanager
def monitor_mode(interface):
    print(f'({interface}) Entering monitor mode...')
    kill_wifi_processes()
    interface = enter_monitor_mode(interface)
    print(f'({interface}) In monitor mode.')
    
    try:
        yield interface 
        
    finally:
        print(f'({interface}) Leaving monitor mode...')
        interface = leave_monitor_mode(interface)
        print(f'({interface}) In managed mode.')
