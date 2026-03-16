import subprocess

from contextlib import contextmanager
from threading import Thread, Event

from constants import *


def set_channel(interface, channel):
    subprocess.run(
        ['iw', 'dev', interface, 'set', 'channel', str(channel)],
        stderr=subprocess.DEVNULL
    )


def hop_channels(interface, delay, stop_event: Event):
    while not stop_event.is_set():
        for channel in CHANNELS_2GHz:
            set_channel(interface, channel)

            stopped = stop_event.wait(timeout=delay)
            if stopped:
                return

@contextmanager
def channel_hopper(interface, delay):
    stop_event = Event()

    hopper_thread = Thread(
        target=hop_channels,
        args=(interface, delay, stop_event),
        daemon=True)
    
    hopper_thread.start()
    print(f'({interface}) Hopping channel every {delay}s...')

    try:
        yield hopper_thread

    finally:
        stop_event.set()
        hopper_thread.join()
        print(f'({interface}) Hopping channels finished.')
