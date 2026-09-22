; checker_test.asm - Windows x64 wordlist + brute-force cracking test harness
; Reuses the verified sha256_hash core unchanged.
; Build: fasm checker_test.asm checker_test.exe
; Usage:
;   checker_test.exe wordlist <target_hex64> <wordlist_path>
;   checker_test.exe brute <target_hex64> <charset> <minlen> <maxlen>

format PE64 console
entry start

include 'INCLUDE/WIN64A.INC'

section '.data' data readable writeable
hStdOut:    dq 0
bytes_done: dd 0
bytes_read: dd 0
cmdline_buf rb 4096
argv_buf:   rq 8
argc_value: dq 0

section '.idata' import data readable writeable
library kernel32,'KERNEL32.DLL'
include 'INCLUDE/API/KERNEL32.INC'

section '.rodata' readable
align 32
k_const:
    dd 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    dd 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    dd 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    dd 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    dd 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    dd 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    dd 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    dd 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
h_init:
    dd 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    dd 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
hex_chars: db "0123456789abcdef"
nl: db 10
msg_progress: db "PROGRESS "
msg_progress_len = $ - msg_progress
msg_found: db "FOUND "
msg_found_len = $ - msg_found
msg_done: db "DONE "
msg_done_len = $ - msg_done
msg_error: db "ERROR "
msg_error_len = $ - msg_error
msg_worker: db "WORKER "
msg_worker_len = $ - msg_worker
msg_space: db " "
msg_space_len = $ - msg_space

section '.bss' readable writeable
pad_buf:   rb 4096
w_buf:     rd 64
hexout:    rb 65
file_buf:  rb 1048576       ; 1MB test buffer for wordlist
digit_arr: rb 64             ; brute-force odometer digits
cand_buf:  rb 65            ; current brute-force candidate string
numbuf:    rb 24             ; scratch for printing numbers
line_length: rq 1
WORK_PAD = 0
WORK_W = 4096
WORK_DIGEST = 4352
WORK_CAND = 4384
WORK_DIGITS = 4448
WORK_ID = 4512
WORK_COUNT = 4520
WORK_STRIDE = 4528
WORK_CHARSET = 4536
WORK_MIN = 4544
WORK_MAX = 4552
WORK_DONE = 4560
WORK_SIZE = 4608
MAX_WORKERS = 64
WORK_CHUNK = 16384
main_ctx rb WORK_SIZE
worker_ctx rb WORK_SIZE*MAX_WORKERS
thread_handles rq MAX_WORKERS
thread_ids rd MAX_WORKERS
system_info rb 48
tls_index dd 0
worker_count dd 0
stop_flag dd 0
found_flag dd 0
total_count rq 1
target_digest rb 32
charset_data rb 65
brute_min dd 0
brute_max dd 0
brute_charset_len dd 0
brute_thread_count dd 0
found_candidate rb 65


section '.text' code readable executable

; ================= sha256_hash (verified core, unchanged) =================
sha256_hash:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 64

    mov [rsp+0], rdx
    mov [rsp+56], r8
    mov r9, r8
    add r9, WORK_PAD
    mov r10, rdi
    mov rcx, rsi
    push rdi
    push rsi
    mov rdi, r9
    mov rsi, r10
    rep movsb
    mov byte [rdi], 0x80
    inc rdi
    pop rsi
    pop rdi

    mov rax, rsi
    add rax, 9
    xor rdx, rdx
    mov rcx, 64
    div rcx
    test rdx, rdx
    jz .no_extra
    inc rax
.no_extra:
    imul rax, rax, 64
    mov [rsp+8], rax

    mov r11, [rsp+56]
    add r11, WORK_PAD
    add r11, rax
    sub r11, 8
.zero_loop:
    cmp rdi, r11
    jge .zero_done
    mov byte [rdi], 0
    inc rdi
    jmp .zero_loop
.zero_done:
    mov rcx, rsi
    shl rcx, 3
    bswap rcx
    mov [r11], rcx

    mov eax, [h_init+0]
    mov [rsp+16+0], eax
    mov eax, [h_init+4]
    mov [rsp+16+4], eax
    mov eax, [h_init+8]
    mov [rsp+16+8], eax
    mov eax, [h_init+12]
    mov [rsp+16+12], eax
    mov eax, [h_init+16]
    mov [rsp+16+16], eax
    mov eax, [h_init+20]
    mov [rsp+16+20], eax
    mov eax, [h_init+24]
    mov [rsp+16+24], eax
    mov eax, [h_init+28]
    mov [rsp+16+28], eax

    xor rbx, rbx
.block_loop:
    mov rax, [rsp+8]
    cmp rbx, rax
    jge .all_blocks_done

    mov rsi, [rsp+56]
    add rsi, WORK_PAD
    add rsi, rbx
    xor rcx, rcx
.load_w:
    cmp rcx, 16
    jge .extend_w
    mov r11, [rsp+56]
    add r11, WORK_W
    mov eax, [rsi + rcx*4]
    bswap eax
    mov [r11 + rcx*4], eax
    inc rcx
    jmp .load_w
.extend_w:
    cmp rcx, 64
    jge .w_done
    mov eax, [r11 + (rcx-15)*4]
    mov edx, eax
    ror edx, 7
    mov r8d, eax
    ror r8d, 18
    xor edx, r8d
    mov r9d, eax
    shr r9d, 3
    xor edx, r9d
    mov eax, [r11 + (rcx-2)*4]
    mov r8d, eax
    ror r8d, 17
    mov r9d, eax
    ror r9d, 19
    xor r8d, r9d
    mov r9d, eax
    shr r9d, 10
    xor r8d, r9d
    mov eax, [r11 + (rcx-16)*4]
    add eax, edx
    add eax, [r11 + (rcx-7)*4]
    add eax, r8d
    mov [r11 + rcx*4], eax
    inc rcx
    jmp .extend_w
.w_done:
    mov r8d,  [rsp+16+0]
    mov r9d,  [rsp+16+4]
    mov r10d, [rsp+16+8]
    mov r11d, [rsp+16+12]
    mov r12d, [rsp+16+16]
    mov r13d, [rsp+16+20]
    mov r14d, [rsp+16+24]
    mov r15d, [rsp+16+28]

    xor rbp, rbp
.round_loop:
    cmp rbp, 64
    jge .rounds_done
    mov ecx, r12d
    ror ecx, 6
    mov edx, r12d
    ror edx, 11
    xor ecx, edx
    mov edx, r12d
    ror edx, 25
    xor ecx, edx
    mov edx, r13d
    and edx, r12d
    mov esi, r12d
    not esi
    and esi, r14d
    xor edx, esi
    mov eax, r15d
    add eax, ecx
    add eax, edx
    add eax, [k_const + rbp*4]
    mov rdx, [rsp+56]
    add rdx, WORK_W
    add eax, [rdx + rbp*4]
    mov ecx, r8d
    ror ecx, 2
    mov edx, r8d
    ror edx, 13
    xor ecx, edx
    mov edx, r8d
    ror edx, 22
    xor ecx, edx
    mov edx, r8d
    and edx, r9d
    mov esi, r8d
    and esi, r10d
    xor edx, esi
    mov esi, r9d
    and esi, r10d
    xor edx, esi
    mov edi, ecx
    add edi, edx
    mov r15d, r14d
    mov r14d, r13d
    mov r13d, r12d
    mov r12d, r11d
    add r12d, eax
    mov r11d, r10d
    mov r10d, r9d
    mov r9d, r8d
    mov r8d, eax
    add r8d, edi
    inc rbp
    jmp .round_loop
.rounds_done:
    add [rsp+16+0],  r8d
    add [rsp+16+4],  r9d
    add [rsp+16+8],  r10d
    add [rsp+16+12], r11d
    add [rsp+16+16], r12d
    add [rsp+16+20], r13d
    add [rsp+16+24], r14d
    add [rsp+16+28], r15d
    add rbx, 64
    jmp .block_loop
.all_blocks_done:
    mov rdi, [rsp+0]
    xor rcx, rcx
.store_loop:
    cmp rcx, 8
    jge .store_done
    mov eax, [rsp+16 + rcx*4]
    bswap eax
    mov [rdi + rcx*4], eax
    inc rcx
    jmp .store_loop
.store_done:
    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; ================= helpers =================

; hex_encode: rdi = 32-byte digest ptr, rsi = out ptr (64 bytes, no null)
hex_encode:
    xor rcx, rcx
.loop:
    cmp rcx, 32
    jge .done
    movzx eax, byte [rdi+rcx]
    mov edx, eax
    shr edx, 4
    lea r8, [hex_chars]
    mov dl, [r8+rdx]
    mov [rsi], dl
    and eax, 0x0f
    lea r8, [hex_chars]
    mov al, [r8+rax]
    mov [rsi+1], al
    add rsi, 2
    inc rcx
    jmp .loop
.done:
    ret

; write_out: rdi = buffer, rsi = length
write_out:
    cmp qword [hStdOut], 0
    jne .stdout_ready
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov [hStdOut], rax
.stdout_ready:
    invoke WriteFile, qword [hStdOut], rdi, rsi, bytes_done, 0
    ret

; print_num: rdi = number (unsigned), writes decimal digits to stdout
print_num:
    lea rsi, [numbuf+23]
    mov byte [rsi], 0
    mov rax, rdi
    mov rcx, 10
.digit_loop:
    xor rdx, rdx
    div rcx
    add dl, '0'
    dec rsi
    mov [rsi], dl
    test rax, rax
    jnz .digit_loop
    ; compute length
    lea rdi, [numbuf+23]
    sub rdi, rsi
    mov rdx, rdi
    mov rdi, rsi
    mov rsi, rdx
    call write_out
    ret

; strlen: rdi = ptr -> returns len in rax
strlen0:
    xor rax, rax
.loop:
    cmp byte [rdi+rax], 0
    je .done
    inc rax
    jmp .loop
.done:
    ret

; ================= wordlist mode =================
; rdi = target hex ptr (64 bytes), rsi = wordlist path ptr
; register plan: r12=target hex ptr, r13=current line-end ptr, r14=file length,
;                r15=word counter, rbx=current line start ptr
; (all of rbx/r12/r13/r14/r15/rbp survive calls to sha256_hash since it saves/restores them.)
wordlist_crack:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi            ; target hex

    invoke CreateFileA, rsi, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    mov r13, rax
    cmp r13, -1
    je .open_err
    invoke ReadFile, r13, file_buf, 1048576, bytes_read, 0
    test eax, eax
    jz .read_err
    mov r14d, [bytes_read]
    invoke CloseHandle, r13

    lea rbx, [file_buf]        ; current line ptr
    xor r15, r15                ; word counter

.line_loop:
    lea rax, [file_buf]
    add rax, r14                ; end of buffer
    cmp rbx, rax
    jge .not_found

    mov rcx, rbx
.scan_loop:
    cmp rcx, rax
    jge .have_line
    cmp byte [rcx], 10
    je .have_line
    inc rcx
    jmp .scan_loop
.have_line:
    mov r13, rcx                ; r13 = untrimmed line-end (safe across all calls below)
    mov rdx, rcx
    cmp rdx, rbx
    jle .empty_line
    cmp byte [rdx-1], 13
    jne .len_ok
    dec rdx
.len_ok:
    mov r8, rdx
    sub r8, rbx                 ; r8 = word length
    test r8, r8
    jz .empty_line
    mov [line_length], r8

    mov rdi, rbx
    mov rsi, r8
    lea r8, [main_ctx]
    lea r8, [pad_buf]
    sub rsp, 32
    lea rdx, [rsp]
    call sha256_hash
    lea rdi, [rsp]
    lea rsi, [hexout]
    call hex_encode
    add rsp, 32

    mov rsi, r12
    lea rdi, [hexout]
    mov rcx, 64
    repe cmpsb
    je .match

    inc r15
    mov rax, r15
    xor rdx, rdx
    mov rcx, 5000
    div rcx
    test rdx, rdx
    jnz .empty_line
    lea rdi, [msg_progress]
    mov rsi, msg_progress_len
    call write_out
    mov rdi, r15
    call print_num
    lea rdi, [nl]
    mov rsi, 1
    call write_out

.empty_line:
    mov rbx, r13
    inc rbx
    jmp .line_loop

.match:
    lea rdi, [msg_found]
    mov rsi, msg_found_len
    call write_out
    mov rdi, rbx
    mov rsi, [line_length]
    call write_out
    lea rdi, [nl]
    mov rsi, 1
    call write_out
    jmp .exit_ok

.not_found:
    lea rdi, [msg_done]
    mov rsi, msg_done_len
    call write_out
    mov rdi, r15
    call print_num
    lea rdi, [nl]
    mov rsi, 1
    call write_out
    jmp .exit_ok

.open_err:
    lea rdi, [msg_error]
    mov rsi, msg_error_len
    call write_out
    lea rdi, [nl]
    mov rsi, 1
    call write_out
    jmp .exit_ok

.read_err:
    invoke CloseHandle, r13
    jmp .open_err

.exit_ok:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ================= brute-force mode =================
; rdi = target hex ptr, rsi = charset ptr, rdx = charset len, rcx = minlen, r8 = maxlen
brute_crack:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp

    mov r12, rdi              ; target hex
    mov r13, rsi              ; charset ptr
    mov rdi, r13
    call strlen0
    mov r14, rax              ; charset len
    mov [line_length], rax    ; preserve charset len across the candidate loop
    mov rbp, rcx                 ; current length = minlen
    ; r8 = maxlen (kept on stack)
    push r8

    xor r15, r15                  ; total tried counter

.len_loop:
    pop rax
    push rax
    cmp rbp, rax
    jg .exhausted

    ; init digit array to 0 for current length
    lea rdi, [digit_arr]
    mov rcx, rbp
    xor rax, rax
    rep stosb

.candidate_loop:
    ; build candidate string from digit_arr using charset
    lea rdi, [cand_buf]
    lea rsi, [digit_arr]
    xor rcx, rcx
.build_loop:
    cmp rcx, rbp
    jge .build_done
    movzx rax, byte [rsi+rcx]
    mov al, [r13+rax]
    mov [rdi+rcx], al
    inc rcx
    jmp .build_loop
.build_done:

    ; hash candidate
    lea rdi, [cand_buf]
    mov rsi, rbp
    lea r8, [main_ctx]
    sub rsp, 32
    lea rdx, [rsp]
    call sha256_hash
    lea rdi, [rsp]
    lea rsi, [hexout]
    call hex_encode
    add rsp, 32

    mov rsi, r12
    lea rdi, [hexout]
    mov rcx, 64
    repe cmpsb
    je .found_it

    inc r15
    mov rax, r15
    xor rdx, rdx
    mov rcx, 20000
    div rcx
    test rdx, rdx
    jnz .no_progress
    lea rdi, [msg_progress]
    mov rsi, msg_progress_len
    call write_out
    mov rdi, r15
    call print_num
    lea rdi, [nl]
    mov rsi, 1
    call write_out
.no_progress:

    ; increment odometer (rightmost digit first)
    mov rcx, rbp
    dec rcx                     ; index of rightmost digit
.carry_loop:
    cmp rcx, -1
    je .len_done                ; overflowed past leftmost -> length exhausted
    lea rdi, [digit_arr]
    movzx rax, byte [rdi+rcx]
    inc rax
    cmp rax, qword [line_length]
    jl .no_carry
    mov byte [rdi+rcx], 0
    dec rcx
    jmp .carry_loop
.no_carry:
    mov [rdi+rcx], al
    jmp .candidate_loop

.len_done:
    inc rbp
    jmp .len_loop

.found_it:
    lea rdi, [msg_found]
    mov rsi, msg_found_len
    call write_out
    lea rdi, [cand_buf]
    mov rsi, rbp
    call write_out
    lea rdi, [nl]
    mov rsi, 1
    call write_out
    jmp .exit_ok

.exhausted:
    lea rdi, [msg_done]
    mov rsi, msg_done_len
    call write_out
    mov rdi, r15
    call print_num
    lea rdi, [nl]
    mov rsi, 1
    call write_out

.exit_ok:
    pop rax
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

emit_worker_progress:
    push rbx
    push r12
    mov r12, rdi
    mov rbx, [r12+WORK_COUNT]
    lea rdi, [msg_worker]
    mov rsi, msg_worker_len
    call write_out
    mov rdi, [r12+WORK_ID]
    call print_num
    lea rdi, [msg_space]
    mov rsi, msg_space_len
    call write_out
    mov rdi, rbx
    call print_num
    lea rdi, [nl]
    mov rsi, 1
    call write_out
    pop r12
    pop rbx
    ret

hex_decode:
    xor rcx, rcx
.loop:
    cmp rcx, 32
    jge .done
    movzx eax, byte [rdi+rcx*2]
    call hex_nibble
    shl eax, 4
    mov edx, eax
    movzx eax, byte [rdi+rcx*2+1]
    call hex_nibble
    or eax, edx
    mov [rsi+rcx], al
    inc rcx
    jmp .loop
.done:
    ret

hex_nibble:
    cmp al, '9'
    jbe .digit
    and al, 0DFh
    sub al, 'A'-10
    ret
.digit:
    sub al, '0'
    ret

; ================= entry =================
brute_worker:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r12, rcx
    lea r13, [charset_data]
    lea r14, [target_digest]
    xor r15, r15
    mov ebp, [r12+WORK_MIN]

.length_loop:
    mov r10, [r12+WORK_MAX]
    cmp ebp, r10d
    jg .worker_done
    mov ebx, [r12+WORK_ID]
.first_digit_loop:
    cmp ebx, [r12+WORK_CHARSET]
    jge .next_length
    mov [r12+WORK_DIGITS], bl
    mov ecx, ebp
    dec ecx
    jle .candidate_loop
    lea rdi, [r12+WORK_DIGITS+1]
    xor eax, eax
    rep stosb

.candidate_loop:
    cmp dword [stop_flag], 0
    jne .worker_done
    lea rdi, [r12+WORK_CAND]
    lea rsi, [r12+WORK_DIGITS]
    xor rcx, rcx
.build_candidate:
    cmp rcx, rbp
    jge .candidate_ready
    movzx eax, byte [rsi+rcx]
    mov al, [r13+rax]
    mov [rdi+rcx], al
    inc rcx
    jmp .build_candidate
.candidate_ready:
    lea rdi, [r12+WORK_CAND]
    mov rsi, rbp
    lea rdx, [r12+WORK_DIGEST]
    mov r8, r12
    call sha256_hash
    lea rdi, [r12+WORK_DIGEST]
    mov rsi, r14
    mov rcx, 32
    repe cmpsb
    je .found

    inc r15
    test r15d, WORK_CHUNK-1
    jnz .advance_candidate
    mov rax, r15
    sub rax, [r12+WORK_COUNT]
    mov [r12+WORK_COUNT], r15
    lock xadd [total_count], rax

.advance_candidate:
    cmp ebp, 1
    je .next_first
    mov ecx, ebp
    dec ecx
.carry_loop:
    cmp ecx, 0
    jle .next_first
    movzx eax, byte [r12+WORK_DIGITS+rcx]
    inc eax
    cmp eax, [r12+WORK_CHARSET]
    jl .store_digit
    mov byte [r12+WORK_DIGITS+rcx], 0
    dec ecx
    jmp .carry_loop
.store_digit:
    mov [r12+WORK_DIGITS+rcx], al
    jmp .candidate_loop

.next_first:
    add ebx, [r12+WORK_STRIDE]
    jmp .first_digit_loop

.next_length:
    inc ebp
    jmp .length_loop

.found:
    mov eax, dword [system_info+32]
    xchg eax, [found_flag]
    test eax, eax
    jnz .worker_done
    lea rdi, [found_candidate]
    lea rsi, [r12+WORK_CAND]
    mov rcx, rbp
    rep movsb
    mov byte [rdi], 0
    mov dword [stop_flag], 1
    jmp .worker_done

.worker_done:
    mov rax, r15
    sub rax, [r12+WORK_COUNT]
    test rax, rax
    jz .worker_return
    mov [r12+WORK_COUNT], r15
    lock xadd [total_count], rax
.worker_return:
    mov qword [r12+WORK_DONE], 1
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    xor eax, eax
    ret

brute_crack_mt:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r14, rsi
    mov [brute_min], ecx
    mov [brute_max], r8d
    mov rdi, r14
    call strlen0
    mov [brute_charset_len], eax
    test eax, eax
    jz .mt_error
    lea rdi, [charset_data]
    mov rsi, r14
    mov rcx, rax
    rep movsb
    mov byte [rdi], 0
    mov rdi, r12
    lea rsi, [target_digest]
    call hex_decode
    lea rdi, [system_info]
    invoke GetSystemInfo, rdi
    mov eax, dword [system_info+32]
    cmp eax, MAX_WORKERS
    jle .worker_count_ok
    mov eax, MAX_WORKERS
.worker_count_ok:
    test eax, eax
    jnz .store_worker_count
    mov eax, 1
.store_worker_count:
    mov [worker_count], eax
    mov [brute_thread_count], eax
    mov dword [stop_flag], 0
    mov dword [found_flag], 0
    mov qword [total_count], 0
    xor ebx, ebx
.create_workers:
    cmp ebx, [worker_count]
    jge .wait_workers
    mov eax, ebx
    imul rax, WORK_SIZE
    lea r13, [worker_ctx+rax]
    mov [r13+WORK_ID], ebx
    mov qword [r13+WORK_COUNT], 0
    mov qword [r13+WORK_DONE], 0
    mov eax, [brute_thread_count]
    mov [r13+WORK_STRIDE], rax
    mov eax, [brute_charset_len]
    mov [r13+WORK_CHARSET], rax
    mov eax, [brute_min]
    mov [r13+WORK_MIN], rax
    mov eax, [brute_max]
    mov [r13+WORK_MAX], rax
    lea r9, [thread_ids+rbx*4]
    invoke CreateThread, 0, 0, brute_worker, r13, 0, r9
    mov [thread_handles+rbx*8], rax
    inc ebx
    jmp .create_workers

.wait_workers:
    call monitor_workers
    xor ebx, ebx
.close_loop:
    cmp ebx, [worker_count]
    jge .mt_result
    invoke WaitForSingleObject, qword [thread_handles+rbx*8], 0FFFFFFFFh
    invoke CloseHandle, qword [thread_handles+rbx*8]
    inc ebx
    jmp .close_loop

.mt_result:
    cmp dword [found_flag], 0
    je .mt_done
    lea rdi, [msg_found]
    mov rsi, msg_found_len
    call write_out
    lea rdi, [found_candidate]
    call strlen0
    mov rsi, rax
    lea rdi, [found_candidate]
    call write_out
    lea rdi, [nl]
    mov rsi, 1
    call write_out
    jmp .mt_exit
.mt_done:
    lea rdi, [msg_done]
    mov rsi, msg_done_len
    call write_out
    mov rdi, [total_count]
    call print_num
    lea rdi, [nl]
    mov rsi, 1
    call write_out
    jmp .mt_exit
.mt_error:
    lea rdi, [msg_error]
    mov rsi, msg_error_len
    call write_out
    lea rdi, [nl]
    mov rsi, 1
    call write_out
.mt_exit:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

monitor_workers:
    push rbx
    push r12
    push r13
    push r14
    push r15
.monitor_loop:
    xor ebx, ebx
    xor r12d, r12d
.scan_workers:
    cmp r12d, [worker_count]
    jge .scan_done
    mov rax, r12
    imul rax, WORK_SIZE
    lea r13, [worker_ctx+rax]
    cmp qword [r13+WORK_DONE], 0
    je .worker_not_done
    inc ebx
.worker_not_done:
    mov rdi, r13
    call emit_worker_progress
    inc r12d
    jmp .scan_workers
.scan_done:
    lea rdi, [msg_progress]
    mov rsi, msg_progress_len
    call write_out
    mov rdi, [total_count]
    call print_num
    lea rdi, [nl]
    mov rsi, 1
    call write_out
    cmp ebx, [worker_count]
    jge .monitor_done
    invoke Sleep, 250
    jmp .monitor_loop
.monitor_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ================= entry =================
start:
    sub rsp, 28h
    invoke GetCommandLineA
    mov rsi, rax
    lea rdi, [cmdline_buf]
.copy_cmdline:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    test al, al
    jnz .copy_cmdline

    lea rsi, [cmdline_buf]
    lea rdi, [argv_buf]
    xor rcx, rcx
.skip_spaces:
    mov al, [rsi]
    cmp al, 0
    je .parsed_args
    cmp al, ' '
    je .skip_one
    cmp al, 9
    je .skip_one
    mov [rdi+rcx*8], rsi
    inc rcx
    cmp al, '"'
    jne .plain_arg
    inc rsi
.quoted_arg:
    mov al, [rsi]
    cmp al, '"'
    je .end_quoted
    cmp al, 0
    je .parsed_args
    inc rsi
    jmp .quoted_arg
.end_quoted:
    mov byte [rsi], 0
    inc rsi
    jmp .skip_spaces
.plain_arg:
    mov al, [rsi]
    cmp al, 0
    je .parsed_args
    cmp al, ' '
    je .end_plain
    cmp al, 9
    je .end_plain
    inc rsi
    jmp .plain_arg
.end_plain:
    mov byte [rsi], 0
    inc rsi
    jmp .skip_spaces
.skip_one:
    inc rsi
    jmp .skip_spaces
.parsed_args:
    mov [argc_value], rcx
    mov rax, rcx
    lea rbx, [argv_buf+8]

    cmp qword [argc_value], 4
    jl .usage_err

    ; check argv[1] == "wordlist" or "brute"
    mov rdi, [rbx]
    lea rsi, [wl_kw]
    call streq
    test rax, rax
    jnz .do_wordlist

    mov rdi, [rbx]
    lea rsi, [br_kw]
    call streq
    test rax, rax
    jnz .do_brute
    jmp .usage_err

.do_wordlist:
    cmp qword [argc_value], 4
    jl .usage_err
    mov rdi, [rbx+8]            ; argv[2] = target hex
    mov rsi, [rbx+16]           ; argv[3] = wordlist path
    call wordlist_crack
    jmp .exit

.do_brute:
    cmp qword [argc_value], 6
    jl .usage_err
    mov rdi, [rbx+16]            ; charset ptr -> compute its length
    call strlen0
    mov rdx, rax                  ; rdx = charset len (strlen0 never modifies rdi)
    mov rsi, rdi                   ; rsi = charset ptr

    mov rdi, [rbx+24]               ; minlen string
    push rdx
    push rsi
    call atoi
    mov rcx, rax                     ; rcx = minlen
    pop rsi
    pop rdx

    push rcx
    mov rdi, [rbx+32]                 ; maxlen string
    call atoi
    mov r8, rax                        ; r8 = maxlen
    pop rcx

    mov rdi, [rbx+8]                    ; target hex
    call brute_crack_mt
    jmp .exit

.usage_err:
    lea rdi, [msg_error]
    mov rsi, msg_error_len
    call write_out

.exit:
    invoke ExitProcess, 0

; streq: rdi,rsi = two null-terminated strings -> rax = 1 if equal else 0
streq:
    xor rcx, rcx
.loop:
    movzx eax, byte [rdi+rcx]
    movzx edx, byte [rsi+rcx]
    cmp eax, edx
    jne .neq
    test eax, eax
    jz .eq
    inc rcx
    jmp .loop
.eq:
    mov rax, 1
    ret
.neq:
    xor rax, rax
    ret

; atoi: rdi = string ptr -> rax = value
atoi:
    xor rax, rax
    xor rcx, rcx
.loop:
    movzx rdx, byte [rdi+rcx]
    test rdx, rdx
    jz .done
    sub rdx, '0'
    imul rax, rax, 10
    add rax, rdx
    inc rcx
    jmp .loop
.done:
    ret

wl_kw: db "wordlist",0
br_kw: db "brute",0