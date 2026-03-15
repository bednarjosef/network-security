import subprocess

def set_channel(interface, channel):
    subprocess.run(
        ['iw', 'dev', interface, 'set', 'channel', str(channel)],
        check=True,
        capture_output=True,
        text=True
    )
    print(f'({interface}) Channel set to {channel}.')
    