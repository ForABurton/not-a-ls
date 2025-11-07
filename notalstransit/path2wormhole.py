#!/usr/bin/env python3
"""
path2wormhole.py

Send or receive files using Magic Wormhole, with optional:
- QR code display for sending
- Direct receive using a wormhole code
- Optional OSC52 clipboard auto-copy (default on)

Usage:
  Send with QR:
    ./path2wormhole.py send myfile.txt --qr

  Receive in interactive mode:
    ./path2wormhole.py receive

  Receive directly using known code:
    ./path2wormhole.py receive <wormhole-code>

"""

import argparse
import subprocess
import sys
import shlex
import os
import base64


def try_show_qr(text):
    """
    Display a QR code in the terminal.
    Attempts in order:
      1) python3 -m qrcode
      2) qrencode CLI
    Falls back silently if neither exists.
    """
    # Try python-qrcode
    try:
        proc = subprocess.Popen(
            ["python3", "-m", "qrcode", "--", text],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        out, _ = proc.communicate(timeout=3)
        if proc.returncode == 0 and out.strip():
            print(out)
            return
    except Exception:
        pass

    # Try qrencode
    try:
        proc = subprocess.Popen(
            ["qrencode", "-t", "ANSIUTF8", text],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        out, _ = proc.communicate(timeout=3)
        if proc.returncode == 0 and out.strip():
            print(out)
            return
    except Exception:
        pass

    # No QR available, silently skip
    return


def osc52_copy(text):
    """
    Copy text to clipboard via OSC52, if the terminal supports it.
    """
    encoded = base64.b64encode(text.encode()).decode()
    sys.stdout.write(f"\x1b]52;c;{encoded}\x07")
    sys.stdout.flush()


def send_file(path, use_qr, do_clip):
    if not os.path.exists(path):
        print(f"ERROR: File not found: {path}", file=sys.stderr)
        sys.exit(1)

    proc = subprocess.Popen(
        ["wormhole", "send", path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1
    )

    code = None

    for line in proc.stdout:
        sys.stdout.write(line)
        sys.stdout.flush()

        if "Wormhole code is:" in line:
            code = line.split(":", 1)[1].strip()

            if do_clip and code:
                osc52_copy(code)

            if use_qr and code:
                print("\n=== QR Code ===\n")
                try_show_qr(code)
                print("\n==============\n")

    proc.wait()
    return proc.returncode


def receive_file(code=None):
    if code:
        return subprocess.call(["wormhole", "receive", code])

    # interactive mode
    proc = subprocess.Popen(
        ["wormhole", "receive"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1
    )
    for line in proc.stdout:
        sys.stdout.write(line)
        sys.stdout.flush()
    return proc.wait()


def main():
    ap = argparse.ArgumentParser(prog="path2wormhole", description="Transfer files using Magic Wormhole.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_send = sub.add_parser("send", help="Send a file")
    ap_send.add_argument("path", help="File path to send")
    ap_send.add_argument("--qr", action="store_true", help="Show wormhole code as terminal QR")
    ap_send.add_argument("--no-clip", action="store_true", help="Disable OSC52 clipboard copy")

    ap_recv = sub.add_parser("receive", help="Receive a file")
    ap_recv.add_argument("code", nargs="?", help="Optional wormhole code to bypass prompt")

    args = ap.parse_args()

    if args.cmd == "send":
        sys.exit(send_file(args.path, use_qr=args.qr, do_clip=not args.no_clip))
    elif args.cmd == "receive":
        sys.exit(receive_file(code=args.code))


if __name__ == '__main__':
    main()

