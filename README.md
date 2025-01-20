# STM32F405 Bootloader CLI Tool

A command-line interface tool for flashing and managing firmware on STM32F405 devices through USB or UART interfaces. This tool supports secure firmware updates with AES encryption and ECDH key exchange.

## Features

- Dual interface support (USB/UART)
- Secure firmware updates using AES-CBC encryption
- ECDH key exchange for secure communication
- Intel HEX file support
- Firmware image creation with versioning
- Device UID verification

## Prerequisites

```bash
pip install -r requirements.txt
```

## Commands

### 1. Flash Command

Flash a firmware image to the device using either USB or UART interface.

#### USB Interface
```bash
python BL_CLI.py flash --interface usb \
                      --product-id <PID> \
                      --vendor-id <VID> \
                      --address <FLASH_ADDR> \
                      --path <HEX_FILE> \
                      [--verbose]
```

Example:
```bash
python BL_CLI.py flash -i usb -pid 0483 -vid 5740 -a 0x08020000 -p firmware.hex -v
```

#### UART Interface
```bash
python BL_CLI.py flash --interface uart \
                      --port <SERIAL_PORT> \
                      --address <FLASH_ADDR> \
                      --path <HEX_FILE> \
                      [--verbose]
```

Example:
```bash
python BL_CLI.py flash -i uart -P /dev/ttyUSB0 -a 0x08020000 -p firmware.hex -v
```

### 2. Image Command

Create an encrypted firmware image with version information.

```bash
python BL_CLI.py image --input <INPUT_HEX> \
                      --output <OUTPUT_FILE> \
                      [--aes-key <KEY>] \
                      [--aes-iv <IV>] \
                      [--magic-number <NUM>] \
                      [--major-version <VER>] \
                      [--minor-version <VER>] \
                      [--patch-version <VER>] \
                      [--verbose]
```

Example:
```bash
python BL_CLI.py image -i input.hex -o firmware.bin -M 1 -m 0 -p 0 -v
```

### 3. Version Command

Display the version of the CLI tool.

```bash
python BL_CLI.py version
```

## Parameters

### Flash Command
- `--interface, -i`: Interface type (usb/uart)
- `--product-id, -pid`: USB product ID in hex (required for USB)
- `--vendor-id, -vid`: USB vendor ID in hex (required for USB)
- `--port, -P`: Serial port (required for UART)
- `--address, -a`: Flash address in hex (required)
- `--path, -p`: Path to the hex file (required)
- `--verbose, -v`: Enable verbose output

### Image Command
- `--input, -i`: Input hex file path
- `--output, -o`: Output binary file path
- `--aes-key, -k`: AES key (default: 000102030405060708090a0b0c0d0e0f)
- `--aes-iv, -iv`: AES IV (default: 000102030405060708090a0b0c0d0e0f)
- `--magic-number, -g`: Magic number (default: 0x01234567)
- `--major-version, -M`: Major version (default: 1)
- `--minor-version, -m`: Minor version (default: 0)
- `--patch-version, -p`: Patch version (default: 0)
- `--verbose, -v`: Enable verbose output

## Error Handling

The tool includes comprehensive error handling for:
- Invalid parameters
- Connection failures
- Communication errors
- Flashing errors
- File format errors

## Security Features

- AES-CBC encryption for all communications
- ECDH key exchange using SECP256R1 curve
- Unique session keys per connection
- Device UID verification
- CRC32 packet validation 