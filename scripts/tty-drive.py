#!/usr/bin/env python3
"""Test helper: run a command with a real controlling terminal (pty) and answer the
confirmation prompt. stdin <- IN file, stdout -> OUT file; the pty carries only the prompt.
usage: tty-drive.py right|wrong IN OUT cmd args...   prints the terminal transcript."""
import os, pty, re, sys
mode, fin, fout, cmd = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
pid, fd = pty.fork()
if pid == 0:
    os.dup2(os.open(fin, os.O_RDONLY), 0)
    os.dup2(os.open(fout, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 1)
    os.execv(cmd[0], cmd)
buf = b""; sent = False
while True:
    try: d = os.read(fd, 4096)
    except OSError: break
    if not d: break
    buf += d
    m = re.search(rb"Type the code (\S+) to confirm", buf)
    if m and not sent:
        os.write(fd, ((m.group(1).decode() if mode == "right" else "nope") + "\n").encode()); sent = True
_, st = os.waitpid(pid, 0)
sys.stdout.write(buf.decode(errors="replace"))
sys.exit(os.waitstatus_to_exitcode(st))
