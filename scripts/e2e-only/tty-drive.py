#!/usr/bin/env python3
"""E2E ONLY. Never install or ship this; it is not a blocktools tool.
It is also the proof of a residual risk: any process that can fork a pty can read the
confirmation code and type it, so /dev/tty alone does not prove a human (SECURITY.md).
Test helper: run a command with a real controlling terminal (pty) and answer the
confirmation prompt. stdin <- IN file, stdout -> OUT file; the pty carries only the prompt.
usage: tty-drive.py right|wrong IN OUT cmd args...   prints the terminal transcript."""
import os, pty, re, sys
mode, fin, fout, cmd = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
pid, fd = pty.fork()
if pid == 0:
    os.dup2(os.open(fin, os.O_RDONLY), 0)
    os.dup2(os.open(fout, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 1)
    os.execv(cmd[0], cmd)
buf = b""; sent = 0  # answers every prompt (recover.sh asks twice: tx-sign, then tx-broadcast)
while True:
    try: d = os.read(fd, 4096)
    except OSError: break
    if not d: break
    buf += d
    ms = re.findall(rb"Type the code (\S+) to confirm", buf)
    if len(ms) > sent:
        os.write(fd, ((ms[sent].decode() if mode == "right" else "nope") + "\n").encode()); sent += 1
_, st = os.waitpid(pid, 0)
sys.stdout.write(buf.decode(errors="replace"))
sys.exit(os.waitstatus_to_exitcode(st))
