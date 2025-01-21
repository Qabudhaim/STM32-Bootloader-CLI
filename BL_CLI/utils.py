import hashlib
import sys
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
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

def display_progress_bar(current, total, start_time, bar_length=30):
    progress = current / total
    elapsed_time = time.time() - start_time
    eta = (elapsed_time / progress - elapsed_time) if progress > 0 else 0
    block = int(bar_length * progress)
    bar = "=" * block + "-" * (bar_length - block)
    sys.stdout.write(
        f"\r[{bar}] {current}/{total} ({progress * 100:.2f}%) | ETA: {eta:.2f}s"
    )
    sys.stdout.flush()

def convert_hex_to_packets(flash_data):
    packets = []
    
    for chunk_offset in range(0, len(flash_data), 32):
        if len(flash_data) - chunk_offset < 32:
            padding_length = 32 - (len(flash_data) - chunk_offset)
            flash_data += bytes([0xFF] * padding_length)

        packet_data = bytearray()
        packet_data.extend(chunk_offset.to_bytes(2, byteorder='little'))
        packet_data.extend(flash_data[chunk_offset:chunk_offset + 32])
        
        packet = create_command_packet(CMD_WRITE_FLASH, packet_data)
        packets.append(packet)

    return packets

def calculate_checksum_crc32(data: bytes) -> bytes:
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

def parse_hex_file(hex_file):
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

def create_image_header(flash_data, magic_number, major_version, minor_version, patch_version):
    magic_number = (magic_number).to_bytes(4, byteorder='little')
    sha256_hash = generate_flash_signature(flash_data)
    length = (len(flash_data)).to_bytes(4, byteorder='little')

    major_version = (major_version).to_bytes(2, byteorder='little')
    minor_version = (minor_version).to_bytes(2, byteorder='little')
    patch_version = (patch_version).to_bytes(2, byteorder='little')

    header = magic_number + sha256_hash + length + major_version + minor_version + patch_version
    padding = b'\x00' * (512 - len(header))

    header += padding
    image = header + flash_data

    return image

def generate_flash_signature(flash_data):
    # Calculate the SHA256 hash of the flash data
    sha256 = hashlib.sha256()
    sha256.update(flash_data)
    sha256_hash = sha256.hexdigest()
    sha256_hash = bytes.fromhex(sha256_hash)

    return sha256_hash

def encrypt_flash_data(data, key, iv):
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes long.")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes long.")

    cipher = AES.new(key, AES.MODE_CBC, iv)

    if len(data) % 16 != 0:
        data = pad(data, AES.block_size)
    
    ct_bytes = cipher.encrypt(data)
    return ct_bytes

def create_command_packet(command, data=None):
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

    crc = calculate_checksum_crc32(packet[3:CRC_OFFSET])
    packet[CRC_OFFSET:CRC_OFFSET+4] = crc

    return bytes(packet)

def derive_aes_key_and_iv(shared_secret, aes_key_len=16, iv_len=16):
    """
    Derive AES key and IV from a shared secret using HKDF.
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
