import serial
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

def initialize_uart_flash(flash_data, port, address, verbose=False):   
    serial_manager = SerialManager()
    if not serial_manager.connect(port):
        click.echo("Failed to connect to serial port.")
        exit()

    data = convert_hex_to_packets(flash_data)  # We can reuse this function as packet format is the same
    handshake_ctx = AESContext(bytes.fromhex('000102030405060708090a0b0c0d0e0f'), 
                              bytes.fromhex('000102030405060708090a0b0c0d0e0f'))

    response, aes_key, iv = perform_uart_handshake(serial_manager, handshake_ctx, verbose)

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
    response = erase_uart_flash_memory(serial_manager, address, len(flash_data), session_ctx)

    if verbose:
        if response[0] == ACK:
            click.echo("→ Flash erased successfully.")
        else:
            click.echo("→ Error erasing flash.")
            exit()

    response = write_uart_flash_memory(serial_manager, data, verbose, session_ctx)

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

    response = finalize_uart_flash(serial_manager, session_ctx)

    if verbose:
        if response[0] == ACK:
            click.echo("→ Flash complete.")
        else:
            click.echo("→ Error flashing.")
            exit()

    response = execute_uart_application(serial_manager, session_ctx)

    if verbose:
        click.echo("→ Jumping to application.")

    serial_manager.disconnect()

def perform_uart_handshake(serial_manager, handshake_ctx, verbose=False):
    # Reset device
    reset_packet = create_command_packet(CMD_RESET)
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
    uid_packet = create_command_packet(CMD_GET_UID)
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
    key_x_packet = create_command_packet(CMD_SEND_PUBLIC_KEY_X, public_key_x)
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
    key_y_packet = create_command_packet(CMD_SEND_PUBLIC_KEY_Y, public_key_y)
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

def erase_uart_flash_memory(serial_manager, start_address, length, session_ctx):
    data = bytearray()
    data.extend(start_address.to_bytes(4, byteorder='little'))
    data.extend(length.to_bytes(4, byteorder='little'))
    
    packet = create_command_packet(CMD_ERASE_FLASH, data)
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

def write_uart_flash_memory(serial_manager, data, verbose, session_ctx):
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
        display_progress_bar(data.index(packet) + 1, len(data), start_time)

    return response

def finalize_uart_flash(serial_manager, session_ctx):
    packet = create_command_packet(CMD_FLASH_DONE)
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

def execute_uart_application(serial_manager, session_ctx):
    packet = create_command_packet(CMD_JUMP_TO_APP)
    packet = session_ctx.encrypt_data(packet)
    try:
        serial_manager.write(packet)
    except Exception as e:
        click.echo(f"→ Serial Error during jump to app write: {str(e)}")
        exit()
