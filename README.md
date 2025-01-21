# Bootloader CLI Tool

A command-line interface tool for bootloader operations, supporting both USB and UART interfaces.

## Project Structure

```
BL_CLI/
├── BL_CLI/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py          # Command-line interface
│   ├── uart_handler.py # UART-specific functionality
│   ├── usb_handler.py  # USB-specific functionality
│   └── utils.py        # Common utilities and constants
├── setup.py           # Package installation
├── README.md         # Package documentation
└── .gitignore       # Git ignore file
```

## Features

- Create encrypted bootloader images
- Flash images via USB or UART
- Support for AES encryption
- Progress bar for flashing operations
- Verbose mode for debugging

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd BL_CLI
```

2. Install the package:
```bash
pip install -e .
```

## Usage

The tool provides three main commands:

### Version

Display the version of the tool:
```bash
bl-cli version
```

### Create Image

Create an encrypted bootloader image:
```bash
bl-cli image -i <input-hex-file> -o <output-file> [options]
```

Options:
- `-i, --input`: Input hex file path (required)
- `-o, --output`: Output file path (required)
- `-k, --aes-key`: AES key for encryption (optional)
- `-iv, --aes-iv`: AES initialization vector (optional)
- `-g, --magic-number`: Magic number for image identification (optional)
- `-M, --major-version`: Major version number (optional)
- `-m, --minor-version`: Minor version number (optional)
- `-p, --patch-version`: Patch version number (optional)
- `-v, --verbose`: Enable verbose output

### Flash Image

Flash an image to a device:
```bash
bl-cli flash -i <interface> -p <image-path> -a <address> [options]
```

Options:
- `-i, --interface`: Interface to use ('usb' or 'uart') (required)
- `-p, --path`: Path to the image file (required)
- `-a, --address`: Flash address in hex (required)
- `-pid, --product-id`: USB product ID (required for USB)
- `-vid, --vendor-id`: USB vendor ID (required for USB)
- `-P, --port`: UART port (required for UART)
- `-v, --verbose`: Enable verbose output

## Examples

1. Create an encrypted image:
```bash
bl-cli image -i firmware.hex -o firmware.bin -k 000102030405060708090a0b0c0d0e0f -iv 000102030405060708090a0b0c0d0e0f -v
```

2. Flash via USB:
```bash
bl-cli flash -i usb -p firmware.hex -a 0x08000000 -pid 0x0483 -vid 0x5740 -v
```

3. Flash via UART:
```bash
bl-cli flash -i uart -p firmware.hex -a 0x08000000 -P /dev/ttyUSB0 -v
```

## Dependencies

- click
- pycryptodome
- pyusb
- pyserial
- cryptography

## Development

For development, you can install the package in editable mode:
```bash
pip install -e .
```

This allows you to modify the code and test changes without reinstalling.

## License

This project is licensed under the MIT License. 