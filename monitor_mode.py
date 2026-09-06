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

# def kill_wifi_processes():
#     subprocess.run(['sudo', 'systemctl', 'stop', 'NetworkManager'])
#     subprocess.run(['sudo', 'systemctl', 'stop', 'wpa_supplicant'])


def isolate_interface(interface):
    subprocess.run(['nmcli', 'device', 'set', interface, 'managed', 'no'], check=True)

def restore_interface(interface):
    subprocess.run(['sudo', 'nmcli', 'device', 'set', interface, 'managed', 'yes'], check=True)


def enter_monitor_mode(interface):
    mon_interface = interface # + 'mon'
    
    isolate_interface(interface)
    subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True)
    subprocess.run(['iw', 'dev', interface, 'set', 'type', 'monitor'], check=True)
    subprocess.run(['ip', 'link', 'set', mon_interface, 'up'], check=True)
    
    return mon_interface 


def leave_monitor_mode(interface):
    base_iface = interface # [:-3]  # strip 'mon' from the end
    
    subprocess.run(['ip', 'link', 'set', interface, 'down'])
    subprocess.run(['iw', 'dev', interface, 'set', 'type', 'managed'])
    subprocess.run(['ip', 'link', 'set', interface, 'up'])
    restore_interface(interface)
    
    return base_iface


@contextmanager
def monitor_mode(interface):
    print(f'({interface}) Entering monitor mode...')

    interface = enter_monitor_mode(interface)
    
    print(f'({interface}) In monitor mode.')
    
    try:
        yield interface 
        
    finally:
        print(f'({interface}) Leaving monitor mode...')

        interface = leave_monitor_mode(interface)
        
        print(f'({interface}) In managed mode.')
