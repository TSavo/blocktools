# E2E-only helpers

Nothing here is installed, packaged or part of the sealed image. `tty-drive.py` drives the
terminal confirmation through a pseudo-terminal so e2e can test tx-sign, sealed-run human and
terminal pinning. It also demonstrates the residual risk documented in docs/SECURITY.md
("Terminal confirmation"): a process that can spawn a pty can type the code.
