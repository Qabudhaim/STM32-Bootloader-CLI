import click
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import usb.core
import usb.util
import time
import sys
import serial

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend

# Version information
MAJOR_VERSION = 1
MINOR_VERSION = 0
PATCH_VERSION = 0

# Protocol constants
START_BYTE = 0x3E
END_BYTE = 0x3C

# Command codes
CMD_RESET = 0x28
CMD_SEND_PUBLIC_KEY_X = 0x26
CMD_SEND_PUBLIC_KEY_Y = 0x27
CMD_ERASE_FLASH = 0x21
CMD_WRITE_FLASH = 0x22
CMD_JUMP_TO_APP = 0x24
CMD_FLASH_DONE = 0x25
CMD_GET_UID = 0x29

# Response codes
ACK = 0x7A
NACK = 0xA5

# Error codes
ERROR_CHECKSUM_INVALID = 0xE0
ERROR_HEADER_INVALID = 0xE1

# Packet constants
PACKET_SIZE = 64
DATA_OFFSET = 3
CRC_OFFSET = 59
HEADER_SIZE = 512
PUBLIC_KEY_SIZE = 32

class AESContext:
    def __init__(self, key, iv):

        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes long.")
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes long.")
    
        self.key = key
        self.iv = iv
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)

    def encrypt_data(self, data):
        if len(data) % 16 != 0:
            data = pad(data, AES.block_size)
        
        ct_bytes = self.cipher.encrypt(data)
        return ct_bytes

    def decrypt_data(self, data):
        pt = self.cipher.decrypt(data)
        return pt
    
    def reset_cipher(self):
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)

class SerialManager:
    def __init__(self):
        self.port = None
        self.serial = None
        self.baudrate = 115200  # Default baudrate
        self.timeout = 2  # Default timeout in seconds

    def connect(self, port):
        self.port = port
        try:
            self.serial = serial.Serial(
                port=port,
                baudrate=self.baudrate,
                timeout=self.timeout,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE
            )

            # flush the serial port
            self.serial.flushInput()
            self.serial.flushOutput()

            return True
        except serial.SerialException as e:
            click.echo(f"Error opening serial port: {str(e)}")
            return False

    def disconnect(self):
        if self.serial and self.serial.is_open:
            self.serial.close()
        self.serial = None

    def write(self, data):
        if not self.serial or not self.serial.is_open:
            raise Exception("Serial port not open")
        return self.serial.write(data)

    def read(self, size=64):
        if not self.serial or not self.serial.is_open:
            raise Exception("Serial port not open")
        return self.serial.read(size)

    def flush(self):
        if self.serial and self.serial.is_open:
            self.serial.flush()

class USBDeviceManager:
    def __init__(self):
        self.device = None
        self.endpoint_out = None
        self.endpoint_in = None

        self.vendor_id = None
        self.product_id = None

    def connect(self, vendor_id, product_id):
        self.vendor_id = vendor_id
        self.product_id = product_id
        self.connect_to_usb_device(vendor_id, product_id)

    def disconnect(self):
        self.device = None
        self.endpoint_out = None
        self.endpoint_in = None

    def connect_to_usb_device(self, vendor_id, product_id):
        if vendor_id is None or product_id is None:
            click.echo("Please provide the vendor ID and product ID of the device.")
            exit()

        # Find the device
        self.device = usb.core.find(idVendor=vendor_id, idProduct=product_id)

        if self.device is None:
            click.echo("Device not found.")
            exit()

        configurations = self.device.get_active_configuration()
        interface = configurations[(1, 0)]

        self.endpoint_out = usb.util.find_descriptor(interface, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT)
        self.endpoint_in = usb.util.find_descriptor(interface, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN)

    def reconnect(self):
        self.connect_to_usb_device(self.vendor_id, self.product_id)

def usb_flash_handler(flash_data, product_id, vendor_id, address, verbose):
    usb_device_manager = USBDeviceManager()
    usb_device_manager.connect(vendor_id, product_id)

    data = hex_to_usb_packets(flash_data)
    handshake_ctx = AESContext(bytes.fromhex('000102030405060708090a0b0c0d0e0f'), 
                              bytes.fromhex('000102030405060708090a0b0c0d0e0f'))

    response, aes_key, iv = usb_handshake(usb_device_manager, handshake_ctx, verbose)

    if verbose:
        if response[0] == ACK:
            click.echo("→ Handshake successful.")
        else:
            click.echo("→ Error during handshake.")
            exit()

    if verbose:
        click.echo("→ Erasing flash...")

    session_ctx = AESContext(aes_key, iv)

    response = usb_erase_flash(usb_device_manager, address, len(flash_data), session_ctx)

    if verbose:
        if response[0] == ACK:
            click.echo("→ Flash erased successfully.")
        else:
            click.echo("→ Error erasing flash.")
            exit()

    response = usb_write_flash(usb_device_manager, data, verbose, session_ctx)

    if verbose:
        click.echo("") # newline 
        if response[0] == ACK:
            click.echo("→ Flash written successfully.")
        else:
            if (response[1] == ERROR_CHECKSUM_INVALID):
                click.echo("→ Error writing to flash. Checksum invalid.")
            elif (response[1] == ERROR_HEADER_INVALID):
                click.echo("→ Error writing to flash. Header invalid.")
            else:                
                click.echo("→ Error writing to flash.")
            exit()

    response = usb_flash_done(usb_device_manager, session_ctx)

    if verbose:
        if response[0] == ACK:
            click.echo("→ Flash complete.")
        else:
            click.echo("→ Error flashing.")
            exit()

    response = usb_jump_to_app(usb_device_manager, session_ctx)

    if verbose:
        click.echo("→ Jumping to application.")


def usb_handshake(usb_device_manager, handshake_ctx, verbose=False):
    # Reset device
    reset_packet = create_packet(CMD_RESET)
    encrypted_reset = handshake_ctx.encrypt_data(reset_packet)
    try:
        usb_device_manager.device.write(usb_device_manager.endpoint_out.bEndpointAddress, encrypted_reset)
    except usb.core.USBError as e:
        if verbose:
            click.echo(f"→ USB Error during reset write: {str(e)}")
        exit()

    handshake_ctx.reset_cipher()

    # Wait for device to disappear and reappear
    if verbose:
        click.echo("→ Waiting for device reset...")
        
    time.sleep(1)  # Initial wait for device to reset
    
    # Check if device exists
    while usb.core.find(idVendor=usb_device_manager.vendor_id, 
                       idProduct=usb_device_manager.product_id) is None:
        time.sleep(0.1)  # Small sleep to prevent CPU spinning
        
    usb_device_manager.reconnect()

    # Read reset response
    try:
        response = usb_device_manager.device.read(usb_device_manager.endpoint_in.bEndpointAddress, 64, timeout=5000)
        response = bytes(response)
    except usb.core.USBError as e:
        if verbose:
            click.echo(f"→ USB Error during reset response: {str(e)}")
        exit()

    if verbose:
        click.echo("→ Reset acknowledged")

    # Get device UID
    uid_packet = create_packet(CMD_GET_UID)
    encrypted_uid_packet = handshake_ctx.encrypt_data(uid_packet)
    try:
        usb_device_manager.device.write(usb_device_manager.endpoint_out.bEndpointAddress, encrypted_uid_packet)
    except usb.core.USBError as e:
        if verbose:
            click.echo(f"→ USB Error during UID request: {str(e)}")
        exit()

    try:
        response = usb_device_manager.device.read(usb_device_manager.endpoint_in.bEndpointAddress, 64, timeout=1000)
        response = bytes(response)
    except usb.core.USBError as e:
        if verbose:
            click.echo(f"→ USB Error during UID read: {str(e)}")
        exit()

    if response[0] != ACK:
        if verbose:
            click.echo("→ Error getting device UID!")
        exit()

    device_uid = response[1:13]  # Extract 12 bytes UID
    if verbose:
        click.echo(f"→ Device UID: {device_uid.hex()}")

    # Generate ECDH keys and perform handshake
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    public_key_x = public_key_bytes[1:33]
    public_key_y = public_key_bytes[33:]

    peer_public_key_x = [0] * 32
    peer_public_key_y = [0] * 32

    # Send public key X
    key_x_packet = create_packet(CMD_SEND_PUBLIC_KEY_X, public_key_x)
    encrypted_key_x = handshake_ctx.encrypt_data(key_x_packet)
    try:
        usb_device_manager.device.write(usb_device_manager.endpoint_out.bEndpointAddress, encrypted_key_x)
    except usb.core.USBError as e:
        if verbose:
            click.echo(f"→ USB Error during key X write: {str(e)}")
        exit()

    # Read public key X response
    try:
        response = usb_device_manager.device.read(usb_device_manager.endpoint_in.bEndpointAddress, 64, timeout=1000)
        response = bytes(response)
    except usb.core.USBError as e:
        if verbose:
            click.echo(f"→ USB Error during key X exchange: {str(e)}")
        exit()

    if response[0] != ACK:
        if verbose:
            click.echo("Error exchanging public key X!")
        exit()

    peer_public_key_x = response[1:33]

    # Send public key Y
    key_y_packet = create_packet(CMD_SEND_PUBLIC_KEY_Y, public_key_y)
    encrypted_key_y = handshake_ctx.encrypt_data(key_y_packet)
    try:
        usb_device_manager.device.write(usb_device_manager.endpoint_out.bEndpointAddress, encrypted_key_y)
    except usb.core.USBError as e:
        if verbose:
            click.echo(f"→ USB Error during key Y write: {str(e)}")
        exit()

    # Read public key Y response
    try:
        response = usb_device_manager.device.read(usb_device_manager.endpoint_in.bEndpointAddress, 64, timeout=1000)
        response = bytes(response)
    except usb.core.USBError as e:
        if verbose:
            click.echo(f"→ USB Error during key Y exchange: {str(e)}")
        exit()

    if response[0] != ACK:
        if verbose:
            click.echo("Error exchanging public key Y!")
        exit()

    peer_public_key_y = response[1:33]

    # Construct peer's public key
    peer_public_key_bytes = bytes([0x04]) + peer_public_key_x + peer_public_key_y
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        peer_public_key_bytes
    )

    if verbose:
        click.echo("→ Key exchange completed")

    # Compute shared secret
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    # Derive AES key and IV
    aes_key, iv = derive_aes_key_and_iv(shared_secret)

    if verbose:
        click.echo("→ Session keys established")

    # Read final ack
    try:
        response = usb_device_manager.device.read(usb_device_manager.endpoint_in.bEndpointAddress, 64, timeout=10000)
        response = bytes(response)
    except usb.core.USBError as e:
        if verbose:
            click.echo(f"→ USB Error during final handshake: {str(e)}")
        exit()

    return response, aes_key, iv

def usb_erase_flash(usb_device_manager, start_address, length, session_ctx):
    data = bytearray()
    data.extend(start_address.to_bytes(4, byteorder='little'))
    data.extend(length.to_bytes(4, byteorder='little'))
    
    packet = create_packet(CMD_ERASE_FLASH, data)
    packet = session_ctx.encrypt_data(packet)
    try:
        usb_device_manager.device.write(usb_device_manager.endpoint_out.bEndpointAddress, packet)
    except usb.core.USBError as e:
        click.echo(f"→ USB Error during erase flash write: {str(e)}")
        exit()

    try:
        response = usb_device_manager.device.read(usb_device_manager.endpoint_in.bEndpointAddress, 64, timeout=1000)
        return bytes(response)
    except usb.core.USBError as e:
        click.echo(f"→ USB Error during erase flash read: {str(e)}")
        exit()

def usb_write_flash(usb_device_manager, data, verbose, session_ctx):
    start_time = time.time()
    for packet in data:
        encrypted_packet = session_ctx.encrypt_data(packet)
        try:        
            usb_device_manager.device.write(usb_device_manager.endpoint_out.bEndpointAddress, encrypted_packet)
        except usb.core.USBError as e:
            if verbose:
                click.echo(f"\n→ USB Error during write flash write: {str(e)}")
            return bytes([NACK])
    
        try:
            response = usb_device_manager.device.read(usb_device_manager.endpoint_in.bEndpointAddress, 64, timeout=1000)
            response = bytes(response)
        except usb.core.USBError as e:
            if verbose:
                click.echo(f"\n→ USB Error during write flash read: {str(e)}")
            return bytes([NACK])

        if response[0] != ACK:
            return response
        time.sleep(0.01)
        progress_bar_with_eta(data.index(packet) + 1, len(data), start_time)

    return response

def usb_flash_done(usb_device_manager, session_ctx):
    packet = create_packet(CMD_FLASH_DONE)
    packet = session_ctx.encrypt_data(packet)
    try:
        usb_device_manager.device.write(usb_device_manager.endpoint_out.bEndpointAddress, packet)
    except usb.core.USBError as e:
        click.echo(f"→ USB Error during flash done write: {str(e)}")
        exit()
    
    try:
        response = usb_device_manager.device.read(usb_device_manager.endpoint_in.bEndpointAddress, 64, timeout=1000)
        return bytes(response)
    except usb.core.USBError as e:
        click.echo(f"→ USB Error during flash done read: {str(e)}")
        exit()

def usb_jump_to_app(usb_device_manager, session_ctx):
    packet = create_packet(CMD_JUMP_TO_APP)
    packet = session_ctx.encrypt_data(packet)
    try:
        usb_device_manager.device.write(usb_device_manager.endpoint_out.bEndpointAddress, packet)
    except usb.core.USBError as e:
        click.echo(f"→ USB Error during jump to app write: {str(e)}")
        exit()
        
def uart_flash_handler(flash_data, port, address, verbose=False):   
    serial_manager = SerialManager()
    if not serial_manager.connect(port):
        click.echo("Failed to connect to serial port.")
        exit()

    data = hex_to_usb_packets(flash_data)  # We can reuse this function as packet format is the same
    handshake_ctx = AESContext(bytes.fromhex('000102030405060708090a0b0c0d0e0f'), 
                              bytes.fromhex('000102030405060708090a0b0c0d0e0f'))

    response, aes_key, iv = uart_handshake(serial_manager, handshake_ctx, verbose)

    if verbose:
        if response[0] == ACK:
            click.echo("→ Handshake successful.")
        else:
            click.echo("→ Error during handshake.")
            exit()

    if verbose:
        click.echo("→ Erasing flash...")

    session_ctx = AESContext(aes_key, iv)

    # Erase flash - assuming starting address 0x08000000 for now
    response = uart_erase_flash(serial_manager, address, len(flash_data), session_ctx)

    if verbose:
        if response[0] == ACK:
            click.echo("→ Flash erased successfully.")
        else:
            click.echo("→ Error erasing flash.")
            exit()

    response = uart_write_flash(serial_manager, data, verbose, session_ctx)

    if verbose:
        click.echo("") # newline 
        if response[0] == ACK:
            click.echo("→ Flash written successfully.")
        else:
            if (response[1] == ERROR_CHECKSUM_INVALID):
                click.echo("→ Error writing to flash. Checksum invalid.")
            elif (response[1] == ERROR_HEADER_INVALID):
                click.echo("→ Error writing to flash. Header invalid.")
            else:                
                click.echo("→ Error writing to flash.")
            exit()

    response = uart_flash_done(serial_manager, session_ctx)

    if verbose:
        if response[0] == ACK:
            click.echo("→ Flash complete.")
        else:
            click.echo("→ Error flashing.")
            exit()

    response = uart_jump_to_app(serial_manager, session_ctx)

    if verbose:
        click.echo("→ Jumping to application.")

    serial_manager.disconnect()

def uart_handshake(serial_manager, handshake_ctx, verbose=False):
    # Reset device
    reset_packet = create_packet(CMD_RESET)
    encrypted_reset = handshake_ctx.encrypt_data(reset_packet)
    try:
        serial_manager.write(encrypted_reset)
    except Exception as e:
        if verbose:
            click.echo(f"→ Serial Error during reset write: {str(e)}")
        exit()

    handshake_ctx.reset_cipher()

    # Wait for device to reset
    if verbose:
        click.echo("→ Waiting for device reset...")
    time.sleep(2)  # Give more time for serial reset

    # Read reset response
    try:
        response = serial_manager.read(64)
        if not response:
            if verbose:
                click.echo("→ No response from device after reset")
            exit()
        response = bytes(response)
    except Exception as e:
        if verbose:
            click.echo(f"→ Serial Error during reset response: {str(e)}")
        exit()

    if verbose:
        click.echo("→ Reset acknowledged")

    # Get device UID
    uid_packet = create_packet(CMD_GET_UID)
    encrypted_uid_packet = handshake_ctx.encrypt_data(uid_packet)
    try:
        serial_manager.write(encrypted_uid_packet)
    except Exception as e:
        if verbose:
            click.echo(f"→ Serial Error during UID request: {str(e)}")
        exit()

    try:
        response = serial_manager.read(64)
        if not response:
            if verbose:
                click.echo("→ No response from device during UID request")
            exit()
        response = bytes(response)
    except Exception as e:
        if verbose:
            click.echo(f"→ Serial Error during UID read: {str(e)}")
        exit()

    if response[0] != ACK:
        if verbose:
            click.echo("→ Error getting device UID!")
        exit()

    device_uid = response[1:13]  # Extract 12 bytes UID
    if verbose:
        click.echo(f"→ Device UID: {device_uid.hex()}")

    # Generate ECDH keys and perform handshake
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    public_key_x = public_key_bytes[1:33]
    public_key_y = public_key_bytes[33:]

    peer_public_key_x = [0] * 32
    peer_public_key_y = [0] * 32

    # Send public key X
    key_x_packet = create_packet(CMD_SEND_PUBLIC_KEY_X, public_key_x)
    encrypted_key_x = handshake_ctx.encrypt_data(key_x_packet)
    try:
        serial_manager.write(encrypted_key_x)
    except Exception as e:
        if verbose:
            click.echo(f"→ Serial Error during key X write: {str(e)}")
        exit()

    # Read public key X response
    try:
        response = serial_manager.read(64)
        if not response:
            if verbose:
                click.echo("→ No response during key X exchange")
            exit()
        response = bytes(response)
    except Exception as e:
        if verbose:
            click.echo(f"→ Serial Error during key X exchange: {str(e)}")
        exit()

    if response[0] != ACK:
        if verbose:
            click.echo("Error exchanging public key X!")
        exit()

    peer_public_key_x = response[1:33]

    # Send public key Y
    key_y_packet = create_packet(CMD_SEND_PUBLIC_KEY_Y, public_key_y)
    encrypted_key_y = handshake_ctx.encrypt_data(key_y_packet)
    try:
        serial_manager.write(encrypted_key_y)
    except Exception as e:
        if verbose:
            click.echo(f"→ Serial Error during key Y write: {str(e)}")
        exit()

    # Read public key Y response
    try:
        response = serial_manager.read(64)
        if not response:
            if verbose:
                click.echo("→ No response during key Y exchange")
            exit()
        response = bytes(response)
    except Exception as e:
        if verbose:
            click.echo(f"→ Serial Error during key Y exchange: {str(e)}")
        exit()

    if response[0] != ACK:
        if verbose:
            click.echo("Error exchanging public key Y!")
        exit()

    peer_public_key_y = response[1:33]

    # Construct peer's public key
    peer_public_key_bytes = bytes([0x04]) + peer_public_key_x + peer_public_key_y
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        peer_public_key_bytes
    )

    if verbose:
        click.echo("→ Key exchange completed")

    # Compute shared secret
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    # Derive AES key and IV
    aes_key, iv = derive_aes_key_and_iv(shared_secret)

    if verbose:
        click.echo("→ Session keys established")

    # Read final ack
    try:
        response = serial_manager.read(64)
        if not response:
            if verbose:
                click.echo("→ No response during final handshake")
            exit()
        response = bytes(response)
    except Exception as e:
        if verbose:
            click.echo(f"→ Serial Error during final handshake: {str(e)}")
        exit()

    return response, aes_key, iv

def derive_aes_key_and_iv(shared_secret, aes_key_len=16, iv_len=16):
    """
    Derive AES key and IV from a shared secret using HKDF.

    :param shared_secret: The shared secret as bytes
    :param aes_key_len: Desired length of the AES key in bytes (default 16)
    :param iv_len: Desired length of the IV in bytes (default 16)
    :return: (aes_key, iv) as bytes
    """
    # Define the salt and info parameters
    salt = b"example_salt\x00"  # Add null byte explicitly
    info = b"aes_key_iv_derivation\x00"  # Add null byte explicitly

    # Ensure total output length matches AES key length + IV length
    total_len = aes_key_len + iv_len

    # Derive key material using HKDF
    hkdf = HKDF(
        algorithm=SHA256(),
        length=total_len,
        salt=None,
        info=None,
        backend=default_backend()
    )

    key_material = hkdf.derive(shared_secret)

    # Split the derived material into AES key and IV
    aes_key = key_material[:aes_key_len]
    iv = key_material[aes_key_len:aes_key_len + iv_len]

    return aes_key, iv

def uart_erase_flash(serial_manager, start_address, length, session_ctx):
    data = bytearray()
    data.extend(start_address.to_bytes(4, byteorder='little'))
    data.extend(length.to_bytes(4, byteorder='little'))
    
    packet = create_packet(CMD_ERASE_FLASH, data)
    packet = session_ctx.encrypt_data(packet)
    try:
        serial_manager.write(packet)
    except Exception as e:
        click.echo(f"→ Serial Error during erase flash write: {str(e)}")
        exit()

    try:
        response = serial_manager.read(64)
        if not response:
            click.echo("→ No response during erase flash")
            exit()
        return bytes(response)
    except Exception as e:
        click.echo(f"→ Serial Error during erase flash read: {str(e)}")
        exit()

def uart_write_flash(serial_manager, data, verbose, session_ctx):
    start_time = time.time()
    for packet in data:
        encrypted_packet = session_ctx.encrypt_data(packet)
        try:        
            serial_manager.write(encrypted_packet)
        except Exception as e:
            if verbose:
                click.echo(f"\n→ Serial Error during write flash write: {str(e)}")
            return bytes([NACK])
    
        try:
            response = serial_manager.read(64)
            if not response:
                if verbose:
                    click.echo("\n→ No response during write flash")
                return bytes([NACK])
            response = bytes(response)
        except Exception as e:
            if verbose:
                click.echo(f"\n→ Serial Error during write flash read: {str(e)}")
            return bytes([NACK])

        if response[0] != ACK:
            return response
        time.sleep(0.01)
        progress_bar_with_eta(data.index(packet) + 1, len(data), start_time)

    return response

def uart_flash_done(serial_manager, session_ctx):
    packet = create_packet(CMD_FLASH_DONE)
    packet = session_ctx.encrypt_data(packet)
    try:
        serial_manager.write(packet)
    except Exception as e:
        click.echo(f"→ Serial Error during flash done write: {str(e)}")
        exit()
    
    try:
        response = serial_manager.read(64)
        if not response:
            click.echo("→ No response during flash done")
            exit()
        return bytes(response)
    except Exception as e:
        click.echo(f"→ Serial Error during flash done read: {str(e)}")
        exit()

def uart_jump_to_app(serial_manager, session_ctx):
    packet = create_packet(CMD_JUMP_TO_APP)
    packet = session_ctx.encrypt_data(packet)
    try:
        serial_manager.write(packet)
    except Exception as e:
        click.echo(f"→ Serial Error during jump to app write: {str(e)}")
        exit()
    


def progress_bar_with_eta(current, total, start_time, bar_length=30):
    progress = current / total
    elapsed_time = time.time() - start_time
    eta = (elapsed_time / progress - elapsed_time) if progress > 0 else 0
    block = int(bar_length * progress)
    bar = "=" * block + "-" * (bar_length - block)
    sys.stdout.write(
        f"\r[{bar}] {current}/{total} ({progress * 100:.2f}%) | ETA: {eta:.2f}s"
    )
    sys.stdout.flush()

def hex_to_usb_packets(flash_data):
    packets = []
    
    for chunk_offset in range(0, len(flash_data), 32):
        if len(flash_data) - chunk_offset < 32:
            padding_length = 32 - (len(flash_data) - chunk_offset)
            flash_data += bytes([0xFF] * padding_length)

        packet_data = bytearray()
        packet_data.extend(chunk_offset.to_bytes(2, byteorder='little'))
        packet_data.extend(flash_data[chunk_offset:chunk_offset + 32])
        
        packet = create_packet(CMD_WRITE_FLASH, packet_data)
        packets.append(packet)

    return packets

def calculate_crc32(data: bytes) -> bytes:
    crc_value = 0xFFFFFFFF

    for byte in data:
        crc_value ^= byte

        for _ in range(8):
            if crc_value & 0x80000000:
                crc_value = (crc_value << 1) ^ 0x04C11DB7
            else:
                crc_value <<= 1

            # Keep crc within 32 bits
            crc_value &= 0xFFFFFFFF

    # Convert the result to a 4-byte array (little-endian)
    return crc_value.to_bytes(4, byteorder='little')


def parse_intel_hex(hex_file):
    flash_data = []
    type_02_count = 0  # Counter for type 02 records

    with open(hex_file, 'r') as file:
        for line in file:
            line = line.strip()
            if line.startswith(':'):
                record_length = int(line[1:3], 16)  # Length of the data
                record_type = int(line[7:9], 16)    # Type of the record
                data = line[9:9 + record_length * 2]  # Extract the data

                if record_type == 0:  # Data record
                    flash_data.append(data)
                elif record_type == 2:  # Extended Linear Address Record
                    type_02_count += 1
                    if type_02_count >= 2:  # Stop after the second type 02 record
                        break

    # Join all the collected data
    flash_data_str = ''.join(flash_data)

    # Convert hex string to actual bytes
    flash_data_bytes = bytes.fromhex(flash_data_str)

    # Check if padding is needed
    if len(flash_data_bytes) % 128 != 0:
        padding_length = 128 - (len(flash_data_bytes) % 128)
        flash_data_bytes += bytes([0xFF] * padding_length)

    return flash_data_bytes

def add_header(flash_data, magic_number, major_version, minor_version, patch_version):
    magic_number = (magic_number).to_bytes(4, byteorder='little')
    sha256_hash = sign_flash_data(flash_data)
    length = (len(flash_data)).to_bytes(4, byteorder='little')

    major_version = (major_version).to_bytes(2, byteorder='little')
    minor_version = (minor_version).to_bytes(2, byteorder='little')
    patch_version = (patch_version).to_bytes(2, byteorder='little')

    header = magic_number + sha256_hash + length + major_version + minor_version + patch_version
    padding = b'\x00' * (512 - len(header))

    header += padding
    image = header + flash_data

    return image

def sign_flash_data(flash_data):
    # Calculate the SHA256 hash of the flash data
    sha256 = hashlib.sha256()
    sha256.update(flash_data)
    sha256_hash = sha256.hexdigest()
    sha256_hash = bytes.fromhex(sha256_hash)

    return sha256_hash

def encrypt_data(data, key, iv):

    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes long.")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes long.")

    cipher = AES.new(key, AES.MODE_CBC, iv)

    if len(data) % 16 != 0:
        data = pad(data, AES.block_size)
    
    ct_bytes = cipher.encrypt(data)
    return ct_bytes

def create_packet(command, data=None):
    """
    Create a packet with command and optional data.
    
    Args:
        command: Command byte
        data: Optional data bytes to include
    
    Returns:
        Bytes object containing the complete packet
    """
    packet = [0] * PACKET_SIZE
    packet[0] = START_BYTE
    packet[1] = command
    packet[-1] = END_BYTE

    if data:
        data_len = len(data)
        packet[2] = data_len  # Set data length
        packet[3:3+data_len] = data  # Copy data

    crc = calculate_crc32(packet[3:CRC_OFFSET])
    packet[CRC_OFFSET:CRC_OFFSET+4] = crc

    return bytes(packet)

@click.group()
def cli():
    """A simple CLI with three sub-commands: --version, --image, and --flash."""
    pass

@cli.command()
def version():
    """Display the version of the application."""
    click.echo(f"Version: {MAJOR_VERSION}.{MINOR_VERSION}.{PATCH_VERSION}")

@cli.command()
@click.option('--input', '-i', type=click.Path(exists=True), required=True, help="Path to the image file.")
@click.option('--output', '-o', type=click.Path(), required=True, help="Path to the output image file.")
@click.option('--aes-key', '-k', type=str, help="AES key to encrypt the image.")
@click.option('--aes-iv', '-iv', type=str, help="AES initialization vector to encrypt the image.")
@click.option('--magic-number', '-g', type=int, help="Magic number to identify the image.")
@click.option('--major-version', '-M', type=int, help="Major version of the image.")
@click.option('--minor-version', '-m', type=int, help="Minor version of the image.")
@click.option('--patch-version', '-p', type=int, help="Patch version of the image.")
@click.option('--verbose', '-v', is_flag=True, help="Enable verbose output for debugging.")
def image(input, output, aes_key, aes_iv, magic_number, major_version, minor_version, patch_version, verbose):
    """Create an image file with the specified parameters."""   

    # get output name by parsing / from input path
    filename = output.split('/')[-1]

    if magic_number is None:
        magic_number = 0x01234567
    
    if major_version is None:
        major_version = 1

    if minor_version is None:
        minor_version = 0

    if patch_version is None:
        patch_version = 0

    if aes_key is None:
        aes_key = '000102030405060708090a0b0c0d0e0f'

    if aes_iv is None:
        aes_iv = '000102030405060708090a0b0c0d0e0f'

    aes_ctx = AESContext(bytes.fromhex(aes_key), bytes.fromhex(aes_iv))

    flash_data = parse_intel_hex(input)
    image = add_header(flash_data, magic_number, major_version, minor_version, patch_version)
    encrypted_image = aes_ctx.encrypt_data(image)

    with open(output, 'wb') as file:
        file.write(encrypted_image)

    if verbose:
        click.echo(f"Image file created: {filename}")
        
def validate_usb_params(product_id, vendor_id):
    """Validate USB parameters."""
    if product_id is None:
        click.echo("Please provide the product ID of the device when using USB interface.")
        exit()

    if vendor_id is None:
        click.echo("Please provide the vendor ID of the device when using USB interface.")
        exit()

    try:
        pid = int(product_id, 16)
        vid = int(vendor_id, 16)
        return pid, vid
    except ValueError:
        click.echo("Product ID and Vendor ID must be valid hexadecimal values.")
        exit()

def validate_uart_params(port):
    """Validate UART parameters."""
    if port is None:
        click.echo("Please provide the serial port when using UART interface.")
        exit()
    return port

def validate_flash_params(address):
    """Validate flash parameters."""
    if address is None:
        click.echo("Please provide the flash address.")
        exit()

    try:
        return int(address, 16)
    except ValueError:
        click.echo("Address must be a valid hexadecimal value.")
        exit()

@cli.command()
@click.option('--interface', '-i', type=click.Choice(['usb', 'uart']), required=True, help="Interface to use for flashing.")
@click.option('--product-id', '-pid', type=str, help="Product ID of the device (required for USB).")
@click.option('--vendor-id', '-vid', type=str, help="Vendor ID of the device (required for USB).")
@click.option('--port', '-P', type=str, help="UART port to use for flashing (required for UART).")
@click.option('--address', '-a', type=str, required=True, help="Address to flash the image (required).")
@click.option('--path', '-p', type=click.Path(exists=True), required=True, help="Path to the image file.")
@click.option('--verbose', '-v', is_flag=True, help="Enable verbose output for debugging.")
def flash(interface, product_id, vendor_id, port, address, path, verbose):
    """Flash the image file to the device."""

    # Validate the path to make sure it ends with .hex
    if not path.endswith('.hex'):
        click.echo("Invalid file format. Please provide a .hex file.")
        exit()

    # Validate and parse flash address
    flash_address = validate_flash_params(address)

    # Open path to get flash data
    with open(path, 'rb') as file:
        flash_data = file.read()

    if interface == 'usb':
        pid, vid = validate_usb_params(product_id, vendor_id)
        usb_flash_handler(flash_data, pid, vid, flash_address, verbose)
    else:  # interface == 'uart'
        port = validate_uart_params(port)
        uart_flash_handler(flash_data, port, flash_address, verbose)


    
if __name__ == '__main__':
    cli()