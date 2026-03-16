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

def kill_wifi_processes():
    subprocess.run(['sudo', 'systemctl', 'stop', 'NetworkManager'], )
    subprocess.run(['sudo', 'systemctl', 'stop', 'wpa_supplicant'], )


def enter_monitor_mode(interface):
    mon_interface = interface + 'mon'
    
    subprocess.run(['iw', 'dev', interface, 'interface', 'add', mon_interface, 'type', 'monitor'])
    subprocess.run(['ip', 'link', 'set', interface, 'down'])
    subprocess.run(['ip', 'link', 'set', mon_interface, 'up'])
    
    return mon_interface 


def leave_monitor_mode(interface):
    base_iface = interface[:-3]  # strip 'mon' from the end
    
    subprocess.run(['sudo', 'iw', 'dev', interface, 'del'], )
    subprocess.run(['sudo', 'ip', 'link', 'set', base_iface, 'up'], )
    subprocess.run(['sudo', 'systemctl', 'start', 'NetworkManager'], )
    
    return base_iface


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
