import click
from BL_CLI.utils import (
    MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION,
    parse_hex_file, create_image_header, encrypt_flash_data,
    AESContext, ERROR_CHECKSUM_INVALID, ERROR_HEADER_INVALID
)
from BL_CLI.usb_handler import initialize_usb_flash
from BL_CLI.uart_handler import initialize_uart_flash

def validate_usb_parameters(product_id, vendor_id):
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

def validate_uart_parameters(port):
    """Validate UART parameters."""
    if port is None:
        click.echo("Please provide the serial port when using UART interface.")
        exit()
    return port

def validate_flash_parameters(address):
    """Validate flash parameters."""
    if address is None:
        click.echo("Please provide the flash address.")
        exit()

    try:
        return int(address, 16)
    except ValueError:
        click.echo("Address must be a valid hexadecimal value.")
        exit()

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

    flash_data = parse_hex_file(input)
    image = create_image_header(flash_data, magic_number, major_version, minor_version, patch_version)
    encrypted_image = encrypt_flash_data(image, bytes.fromhex(aes_key), bytes.fromhex(aes_iv))

    with open(output, 'wb') as file:
        file.write(encrypted_image)

    if verbose:
        click.echo(f"Image file created: {filename}")

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
    flash_address = validate_flash_parameters(address)

    # Open path to get flash data
    with open(path, 'rb') as file:
        flash_data = file.read()

    if interface == 'usb':
        pid, vid = validate_usb_parameters(product_id, vendor_id)
        initialize_usb_flash(flash_data, pid, vid, flash_address, verbose)
    else:  # interface == 'uart'
        port = validate_uart_parameters(port)
        initialize_uart_flash(flash_data, port, flash_address, verbose)

if __name__ == '__main__':
    cli()
