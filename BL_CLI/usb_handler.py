import usb.core
import usb.util
import time
import click
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from BL_CLI.utils import (
    ACK, NACK, CMD_RESET, CMD_GET_UID, CMD_SEND_PUBLIC_KEY_X,
    CMD_SEND_PUBLIC_KEY_Y, CMD_ERASE_FLASH, CMD_WRITE_FLASH,
    CMD_FLASH_DONE, CMD_JUMP_TO_APP, convert_hex_to_packets,
    create_command_packet, derive_aes_key_and_iv, display_progress_bar,
    AESContext, ERROR_CHECKSUM_INVALID, ERROR_HEADER_INVALID
)

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

def initialize_usb_flash(flash_data, product_id, vendor_id, address, verbose):
    usb_device_manager = USBDeviceManager()
    usb_device_manager.connect(vendor_id, product_id)

    data = convert_hex_to_packets(flash_data)
    handshake_ctx = AESContext(bytes.fromhex('000102030405060708090a0b0c0d0e0f'), 
                              bytes.fromhex('000102030405060708090a0b0c0d0e0f'))

    response, aes_key, iv = perform_usb_handshake(usb_device_manager, handshake_ctx, verbose)

    if verbose:
        if response[0] == ACK:
            click.echo("→ Handshake successful.")
        else:
            click.echo("→ Error during handshake.")
            exit()

    if verbose:
        click.echo("→ Erasing flash...")

    session_ctx = AESContext(aes_key, iv)

    response = erase_usb_flash_memory(usb_device_manager, address, len(flash_data), session_ctx)

    if verbose:
        if response[0] == ACK:
            click.echo("→ Flash erased successfully.")
        else:
            click.echo("→ Error erasing flash.")
            exit()

    response = write_usb_flash_memory(usb_device_manager, data, verbose, session_ctx)

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

    response = finalize_usb_flash(usb_device_manager, session_ctx)

    if verbose:
        if response[0] == ACK:
            click.echo("→ Flash complete.")
        else:
            click.echo("→ Error flashing.")
            exit()

    response = execute_usb_application(usb_device_manager, session_ctx)

    if verbose:
        click.echo("→ Jumping to application.")

def perform_usb_handshake(usb_device_manager, handshake_ctx, verbose=False):
    # Reset device
    reset_packet = create_command_packet(CMD_RESET)
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
    uid_packet = create_command_packet(CMD_GET_UID)
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
    key_x_packet = create_command_packet(CMD_SEND_PUBLIC_KEY_X, public_key_x)
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
    key_y_packet = create_command_packet(CMD_SEND_PUBLIC_KEY_Y, public_key_y)
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

def erase_usb_flash_memory(usb_device_manager, start_address, length, session_ctx):
    data = bytearray()
    data.extend(start_address.to_bytes(4, byteorder='little'))
    data.extend(length.to_bytes(4, byteorder='little'))
    
    packet = create_command_packet(CMD_ERASE_FLASH, data)
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

def write_usb_flash_memory(usb_device_manager, data, verbose, session_ctx):
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
        display_progress_bar(data.index(packet) + 1, len(data), start_time)

    return response

def finalize_usb_flash(usb_device_manager, session_ctx):
    packet = create_command_packet(CMD_FLASH_DONE)
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

def execute_usb_application(usb_device_manager, session_ctx):
    packet = create_command_packet(CMD_JUMP_TO_APP)
    packet = session_ctx.encrypt_data(packet)
    try:
        usb_device_manager.device.write(usb_device_manager.endpoint_out.bEndpointAddress, packet)
    except usb.core.USBError as e:
        click.echo(f"→ USB Error during jump to app write: {str(e)}")
        exit()
