#!/usr/bin/env python3
"""
fskradioroom.py

Toy acoustic FSK modem for sending/receiving files using speakers <-> microphone.

Usage:
  Transmit:
    ./fskradioroom.py send path/to/file.bin

  Receive:
    ./fskradioroom.py receive --out received.bin

  List audio devices:
    ./fskradioroom.py --list-devices
"""
from __future__ import annotations
import argparse
import sys
import time
import struct
import zlib
import math
import logging
from typing import Iterable, Tuple, Optional

import numpy as np
import pyaudio

# --- Defaults (configurable via CLI) ---
MAGIC = b"RADIOROOM"
DEFAULT_SAMPLE_RATE = 44100
DEFAULT_SYMBOL_DURATION = 0.06   # seconds per symbol (bit)
DEFAULT_FREQ0 = 1200.0
DEFAULT_FREQ1 = 2200.0
DEFAULT_PREAMBLE_FREQ = 1700.0
DEFAULT_PREAMBLE_SECONDS = 1.2
DEFAULT_AMPLITUDE = 0.5

# --- Logging setup ---
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("radiomodem")


# --- Utilities: bits/bytes/frame conversions ---
def bytes_to_bits_le(bts: bytes) -> Iterable[int]:
    """Yield bits LSB-first per byte."""
    for by in bts:
        for i in range(8):
            yield (by >> i) & 1


def bits_to_bytes_le(bits: Iterable[int]) -> bytes:
    """Accumulate bits LSB-first into bytes. Pads with zeros at the end if needed."""
    out = bytearray()
    cur = 0
    bitpos = 0
    for bit in bits:
        cur |= (bit & 1) << bitpos
        bitpos += 1
        if bitpos == 8:
            out.append(cur)
            cur = 0
            bitpos = 0
    if bitpos:
        out.append(cur)
    return bytes(out)


# --- Packet helpers ---
def make_packet(payload: bytes) -> bytes:
    length = len(payload)
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    header = MAGIC + struct.pack(">I", length) + struct.pack(">I", crc)
    return header + payload


def parse_packet_at_front(data: bytes) -> Optional[Tuple[bytes, bool, int]]:
    """
    If a valid packet starts at the front of `data`, return (payload, ok_crc, bytes_used).
    Otherwise return None.
    """
    header_len = len(MAGIC) + 8
    if len(data) < header_len:
        return None
    if data[:len(MAGIC)] != MAGIC:
        return None
    length = struct.unpack(">I", data[len(MAGIC):len(MAGIC)+4])[0]
    crc = struct.unpack(">I", data[len(MAGIC)+4:len(MAGIC)+8])[0]
    needed = header_len + length
    if len(data) < needed:
        return None
    payload = data[header_len:needed]
    ok = (zlib.crc32(payload) & 0xFFFFFFFF) == crc
    return payload, ok, needed


# --- DSP: waveform generation and Goertzel detector ---
def generate_symbol_sines(sample_rate: int, symbol_samples: int, freq0: float, freq1: float) -> Tuple[np.ndarray, np.ndarray]:
    """
    Precompute one-symbol sinusoids for freq0 and freq1 (float32).
    Returns (sin0, sin1) arrays of length symbol_samples.
    """
    t = np.arange(symbol_samples) / float(sample_rate)
    sin0 = np.sin(2.0 * np.pi * freq0 * t).astype(np.float32)
    sin1 = np.sin(2.0 * np.pi * freq1 * t).astype(np.float32)
    # apply small fade envelope to reduce clicks
    ramp = int(min(64, max(4, symbol_samples // 16)))
    env = np.ones(symbol_samples, dtype=np.float32)
    env[:ramp] = np.linspace(0.0, 1.0, ramp)
    env[-ramp:] = np.linspace(1.0, 0.0, ramp)
    sin0 *= env
    sin1 *= env
    return sin0, sin1


def goertzel_power(frame: np.ndarray, sample_rate: int, target_freq: float) -> float:
    """
    Compute power at `target_freq` in `frame` using Goertzel algorithm.
    `frame` is a 1-D numpy array (float32 or float64).
    Returns squared magnitude (power).
    """
    n = frame.shape[0]
    k = int(0.5 + (n * target_freq) / sample_rate)
    omega = (2.0 * math.pi * k) / n
    coeff = 2.0 * math.cos(omega)
    s_prev = 0.0
    s_prev2 = 0.0
    for sample in frame:
        s = sample + coeff * s_prev - s_prev2
        s_prev2 = s_prev
        s_prev = s
    real = s_prev - s_prev2 * math.cos(omega)
    imag = s_prev2 * math.sin(omega)
    return real * real + imag * imag


# --- Transmit path ---
def send_file(path: str,
              sample_rate: int = DEFAULT_SAMPLE_RATE,
              symbol_duration: float = DEFAULT_SYMBOL_DURATION,
              freq0: float = DEFAULT_FREQ0,
              freq1: float = DEFAULT_FREQ1,
              preamble_freq: float = DEFAULT_PREAMBLE_FREQ,
              preamble_seconds: float = DEFAULT_PREAMBLE_SECONDS,
              amplitude: float = DEFAULT_AMPLITUDE,
              device_index: Optional[int] = None):
    """Transmit a file as FSK-modulated audio through the default output (or given device)."""
    if not path or path == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(path, "rb") as f:
            data = f.read()

    pkt = make_packet(data)
    bits = list(bytes_to_bits_le(pkt))  # LSB-first per byte

    # runtime derived
    symbol_samples = int(round(sample_rate * symbol_duration))
    sin0, sin1 = generate_symbol_sines(sample_rate, symbol_samples, freq0, freq1)

    pa = pyaudio.PyAudio()
    try:
        stream = pa.open(format=pyaudio.paFloat32,
                         channels=1,
                         rate=sample_rate,
                         output=True,
                         output_device_index=device_index,
                         frames_per_buffer=min(1024, symbol_samples))
    except Exception as e:
        logger.error("Failed to open audio output: %s", e)
        pa.terminate()
        return

    # Preamble tone (continuous sine at preamble_freq)
    logger.info("TX: playing preamble %.2fs @ %.1fHz", preamble_seconds, preamble_freq)
    pre_samples = int(round(preamble_seconds * sample_rate))
    t = np.arange(pre_samples) / float(sample_rate)
    pre_tone = (amplitude * np.sin(2.0 * np.pi * preamble_freq * t)).astype(np.float32)
    stream.write(pre_tone.tobytes())

    # Send bits in streaming small chunks of symbols
    total_bits = len(bits)
    logger.info("TX: sending %d bytes -> %d bits (approx %.1fs)", len(pkt), total_bits, total_bits * symbol_duration)
    pos = 0
    chunk_symbols = 2048  # symbols per chunk (tunable)
    while pos < total_bits:
        chunk_end = min(total_bits, pos + chunk_symbols)
        chunk = bits[pos:chunk_end]
        # allocate buffer for chunk
        out = np.empty(len(chunk) * symbol_samples, dtype=np.float32)
        for i, b in enumerate(chunk):
            src = sin1 if b else sin0
            out[i*symbol_samples:(i+1)*symbol_samples] = amplitude * src
        stream.write(out.tobytes())
        pos = chunk_end

    # trailing silence
    silence = np.zeros(int(0.15 * sample_rate), dtype=np.float32)
    stream.write(silence.tobytes())
    stream.stop_stream()
    stream.close()
    pa.terminate()
    logger.info("TX: done")


# --- Receive path ---
def receive_listen(out_path: Optional[str] = None,
                   timeout: Optional[float] = None,
                   device_index: Optional[int] = None,
                   sample_rate: int = DEFAULT_SAMPLE_RATE,
                   symbol_duration: float = DEFAULT_SYMBOL_DURATION,
                   freq0: float = DEFAULT_FREQ0,
                   freq1: float = DEFAULT_FREQ1,
                   preamble_freq: float = DEFAULT_PREAMBLE_FREQ,
                   preamble_seconds: float = DEFAULT_PREAMBLE_SECONDS,
                   amplitude: float = DEFAULT_AMPLITUDE) -> bool:
    """
    Listen on microphone and attempt to recover a packet. Returns True if a valid packet was written.
    """

    symbol_samples = int(round(sample_rate * symbol_duration))
    # buffer sizes and limits
    max_bytes_buffer = 2_000_000  # maximum bytes to store before trimming (to avoid memory explosion)
    bytes_buffer = bytearray()

    pa = pyaudio.PyAudio()
    try:
        stream = pa.open(format=pyaudio.paInt16,
                         channels=1,
                         rate=sample_rate,
                         input=True,
                         frames_per_buffer=symbol_samples,
                         input_device_index=device_index)
    except Exception as e:
        logger.error("Failed to open audio input: %s", e)
        pa.terminate()
        return False

    logger.info("RX: listening (symbol %.4fs, %d samples/symbol)...", symbol_duration, symbol_samples)
    start_time = time.time()

    # preamble detection variables
    preamble_detected = False
    preamble_hold_count = max(1, int(0.02 / symbol_duration))  # require some consecutive detections in short windows
    preamble_consec = 0
    preamble_min_energy = None

    bit_buffer = []  # store decoded bits (LSB-first)
    try:
        while True:
            if timeout and (time.time() - start_time) > timeout and not preamble_detected:
                logger.info("RX: timeout waiting for preamble")
                break
            raw = stream.read(symbol_samples, exception_on_overflow=False)
            frame = np.frombuffer(raw, dtype=np.int16).astype(np.float32) / 32768.0

            # compute goertzel power at preamble freq and at bit freqs
            p_pre = goertzel_power(frame, sample_rate, preamble_freq)
            # initialize adaptive baseline on first few frames
            if preamble_min_energy is None:
                preamble_min_energy = p_pre
                # short continue to collect baseline
                preamble_consec = 0

            # adaptive check: look for p_pre >> baseline
            # use ratio threshold rather than absolute to adapt to mic levels
            ratio = (p_pre / (preamble_min_energy + 1e-12)) if preamble_min_energy is not None else float('inf')
            # update baseline slowly (exponential moving average) when no preamble present
            if ratio < 3.0:  # not a strong preamble
                preamble_min_energy = 0.995 * preamble_min_energy + 0.005 * p_pre

            if not preamble_detected:
                if ratio > 8.0:  # empirical threshold: adjust if needed
                    preamble_consec += 1
                    if preamble_consec >= preamble_hold_count:
                        preamble_detected = True
                        logger.info("RX: preamble detected (ratio %.1f). Starting symbol sync.", ratio)
                        # do not attempt to parse this frame as a data symbol; continue to next frame
                        bit_buffer = []
                        bytes_buffer = bytearray()
                        continue
                else:
                    preamble_consec = 0
                    continue

            # after preamble detected: decode this frame as a bit using goertzel for freq0 & freq1
            p0 = goertzel_power(frame, sample_rate, freq0)
            p1 = goertzel_power(frame, sample_rate, freq1)
            bit = 1 if p1 > p0 else 0
            bit_buffer.append(bit)

            # whenever we have full bytes, convert and append to byte buffer (do it incrementally)
            if len(bit_buffer) >= 8:
                # consume as many full bytes as possible from the left
                n_full = len(bit_buffer) // 8
                # build bytes for earliest full bytes
                # take first n_full*8 bits
                to_consume = bit_buffer[:n_full*8]
                bts = bits_to_bytes_le(to_consume)
                bytes_buffer.extend(bts)
                # remove consumed bits
                bit_buffer = bit_buffer[n_full*8:]

                # keep bytes_buffer at a reasonable size (sliding)
                if len(bytes_buffer) > max_bytes_buffer:
                    # keep only the tail
                    bytes_buffer = bytes_buffer[-200_000:]

                # search for MAGIC anywhere in bytes_buffer
                idx = bytes_buffer.find(MAGIC)
                if idx != -1:
                    candidate = bytes(bytes_buffer[idx:])  # from magic to end
                    parsed = parse_packet_at_front(candidate)
                    if parsed:
                        payload, ok, used = parsed
                        if ok:
                            outp = out_path or ("received_%d.bin" % int(time.time()))
                            with open(outp, "wb") as f:
                                f.write(payload)
                            logger.info("RX: received valid packet, wrote %s (%d bytes)", outp, len(payload))
                            stream.stop_stream()
                            stream.close()
                            pa.terminate()
                            return True
                        else:
                            logger.warning("RX: candidate packet found but CRC mismatch (continuing).")
                            # remove bytes up to idx+1 to continue searching progressively
                            del bytes_buffer[:idx+1]
                    else:
                        # not enough bytes yet to parse full packet; continue listening
                        pass

    except KeyboardInterrupt:
        logger.info("RX: interrupted by user")
    except Exception as e:
        logger.exception("RX: error during receive: %s", e)
    finally:
        try:
            stream.stop_stream()
            stream.close()
        except Exception:
            pass
        pa.terminate()

    logger.info("RX: finished without receiving valid packet")
    return False


# --- Helper: list audio devices ---
def list_audio_devices():
    pa = pyaudio.PyAudio()
    try:
        logger.info("Available audio devices:")
        for i in range(pa.get_device_count()):
            info = pa.get_device_info_by_index(i)
            name = info.get("name", "")
            is_input = info.get("maxInputChannels", 0) > 0
            is_output = info.get("maxOutputChannels", 0) > 0
            logger.info("  #%2d: %s   (in:%d out:%d)", i, name, info.get("maxInputChannels", 0), info.get("maxOutputChannels", 0))
    finally:
        pa.terminate()


# --- CLI ---
def build_parser():
    p = argparse.ArgumentParser(prog="fskradioroom", description="Play/listen to a simple acoustic FSK modem.")
    p.add_argument("--list-devices", action="store_true", help="List available audio devices and exit")
    p.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    sub = p.add_subparsers(dest="cmd", required=False)

    tx = sub.add_parser("send", help="Play a file as sound")
    tx.add_argument("path", help="Path to file to send; use - for stdin")
    tx.add_argument("--device", type=int, help="Output device index (optional)")
    tx.add_argument("--sample-rate", type=int, default=DEFAULT_SAMPLE_RATE)
    tx.add_argument("--symbol-duration", type=float, default=DEFAULT_SYMBOL_DURATION)
    tx.add_argument("--freq0", type=float, default=DEFAULT_FREQ0)
    tx.add_argument("--freq1", type=float, default=DEFAULT_FREQ1)
    tx.add_argument("--preamble-freq", type=float, default=DEFAULT_PREAMBLE_FREQ)
    tx.add_argument("--preamble-seconds", type=float, default=DEFAULT_PREAMBLE_SECONDS)
    tx.add_argument("--amplitude", type=float, default=DEFAULT_AMPLITUDE)

    rx = sub.add_parser("receive", help="Listen and try to recover a file")
    rx.add_argument("--out", help="Output file path (optional)", default=None)
    rx.add_argument("--timeout", type=float, help="Seconds to wait for preamble (default: none)", default=None)
    rx.add_argument("--device", type=int, help="Input device index (optional)")
    rx.add_argument("--sample-rate", type=int, default=DEFAULT_SAMPLE_RATE)
    rx.add_argument("--symbol-duration", type=float, default=DEFAULT_SYMBOL_DURATION)
    rx.add_argument("--freq0", type=float, default=DEFAULT_FREQ0)
    rx.add_argument("--freq1", type=float, default=DEFAULT_FREQ1)
    rx.add_argument("--preamble-freq", type=float, default=DEFAULT_PREAMBLE_FREQ)
    rx.add_argument("--preamble-seconds", type=float, default=DEFAULT_PREAMBLE_SECONDS)
    rx.add_argument("--amplitude", type=float, default=DEFAULT_AMPLITUDE)
    tx.add_argument("--subultrasonic", action="store_true",
                    help="Use ~17-19 kHz near-inaudible FSK mode")

    rx.add_argument("--subultrasonic", action="store_true",
                    help="Use ~17-19 kHz near-inaudible FSK mode")

    return p


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "verbose", False):
        logger.setLevel(logging.DEBUG)

    if getattr(args, "list_devices", False):
        list_audio_devices()
        return

    if args.cmd == "send":
        if getattr(args, "subultrasonic", False):
            args.sample_rate = 48000
            args.freq0 = 17000
            args.freq1 = 19000
            args.preamble_freq = 18000
            args.symbol_duration = 0.015

        send_file(args.path,
                  sample_rate=args.sample_rate,
                  symbol_duration=args.symbol_duration,
                  freq0=args.freq0,
                  freq1=args.freq1,
                  preamble_freq=args.preamble_freq,
                  preamble_seconds=args.preamble_seconds,
                  amplitude=args.amplitude,
                  device_index=getattr(args, "device", None))

    elif args.cmd == "receive":
        if getattr(args, "subultrasonic", False):
            args.sample_rate = 48000
            args.freq0 = 17000
            args.freq1 = 19000
            args.preamble_freq = 18000
            args.symbol_duration = 0.015

        ok = receive_listen(out_path=args.out,
                            timeout=args.timeout,
                            device_index=getattr(args, "device", None),
                            sample_rate=args.sample_rate,
                            symbol_duration=args.symbol_duration,
                            freq0=args.freq0,
                            freq1=args.freq1,
                            preamble_freq=args.preamble_freq,
                            preamble_seconds=args.preamble_seconds,
                            amplitude=args.amplitude)
        if not ok:
            logger.info("No valid packet recovered.")
    else:
        parser.print_help()



if __name__ == "__main__":
    main()

