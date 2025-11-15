"""
NotalsTransitHubHub.py

Unified multi-transport adapter layer for:
  - SCPBack (OSC-1337 + scp fallback)
  - Wormhole
  - OSC1337 rz/sz (terminal modem)
  - FSK Radio Room (acoustic modem)

Each adapter implements:
    can_pull(ctx)
    pull(ctx, remote_path, destdir)
    provide_transfer(ctx, path)

The transport logic itself lives in:
    scpback.py
    path2wormhole.py
    rzsz1337modem.py
    fskradioroom.py
"""

import os
import sys
import time
import shutil
import subprocess

from notals import ThingTools
from notals import ThingToolsTool
import importlib.util 
###############################################################################
# Notal Transit Hub
###############################################################################

class NotalsTransitHub(ThingTools):
    name = "Transit Hub"
    priority = 60

    """
    Detects transport/teleport mechanisms located in ./notalstransit/*.py
    and exposes:
      (1) Tools to send/teleport files back to local or another machine.
      (2) A "transfer_path_hook" for other parts of the system (Kitty fallback).

    Modules are normal python files that implement one or more of:
      - can_pull(ctx) -> bool
      - pull(ctx, path, destdir) -> (ok, message)
      - can_push(ctx) -> bool
      - push(ctx, srcpath, target) -> (ok, message)
      - resolve_path(ctx, path) -> (ok, resolvedpath or None, message)
      - provide_transfer(ctx, path) -> (ok, message)
    All methods optional. Hub will gracefully skip modules lacking hooks.
    """

    def __init__(self):
        super().__init__()
        self.modules = []
        self._loaded = False

    def _discover_modules(self):
        """Lazy-load transit modules from ./notalstransit/."""
        if self._loaded:
            return
        self._loaded = True

        base = os.path.join(os.getcwd(), "notalstransit")
        if not os.path.isdir(base):
            return

        for fn in os.listdir(base):
            if not fn.endswith(".py") or fn.startswith("_"):
                continue
            path = os.path.join(base, fn)
            modname = f"notalstransit_{fn[:-3]}"
            try:
                spec = importlib.util.spec_from_file_location(modname, path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                self.modules.append(mod)
            except Exception as e:
                # Don’t crash; report in debug mode but continue
                pass #sys.stderr.write(f"[TransitHub] Failed loading {fn}: {e}")

    @staticmethod
    def priority():
        # Show fairly high in tool list, but before most
        return 60

    @staticmethod
    def name():
        return "Transit Hub"

    def available(self, ctx):
        """Transit hub is always available — individual modules decide capabilities."""
        return True

    def _teleportable_file(self, ctx):
        """Return selected file or None if nothing reasonable selected."""
        if ctx.selected_file:
            p = os.path.join(ctx.cwd, ctx.selected_file)
            if os.path.isfile(p):
                return p
        return None

    def tools(self, ctx):
        self._discover_modules()
        tools = []
        chosen = self._teleportable_file(ctx)
        if chosen:
            tools += [
                TeleportReceiveTool(self, chosen),
                SendFileTool(self, chosen),
                AutoTransferTool(self)
            ]
        return tools


    def detect(self, cwd, system_info):
        return True



    # ----------------------------------------------------------------------
    # (1) Teleport a file back to local or other machine
    # ----------------------------------------------------------------------
    def _tool_teleport_file(self, ctx, path):
        self._discover_modules()
        ui = ctx.ui
        filename = os.path.basename(path)

        # Ask user where to put the file (local dir)
        dest = ui.inbox(
            prompt=f"Destination directory for {filename}:",
            initial=os.getcwd()
        )
        if not dest:
            return ui.show_message("Teleport cancelled.")
        if not os.path.isdir(dest):
            return ui.show_message("That destination directory does not exist.")

        # Ask user what transport method to use
        names = []
        funcs = []
        for mod in self.modules:
            if hasattr(mod, "can_pull") and hasattr(mod, "pull"):
                try:
                    if mod.can_pull(ctx):
                        names.append(f"{mod.__name__}")
                        funcs.append((mod, mod.pull))
                except Exception:
                    pass

        if not names:
            return ui.show_message("No transit modules available.")

        idx = ui.menu(title="Choose transfer method", items=names)
        if idx is None:
            return ui.show_message("Teleport cancelled.")

        mod, pullfn = funcs[idx]

        # Actually attempt to move file
        try:
            ok, msg = pullfn(ctx, path, dest)
        except Exception as e:
            return ui.show_message(f"{mod.__name__} failed: {e}")

        if ok:
            ui.show_message(f"Teleport succeeded: {msg}")
        else:
            ui.show_message(f"Teleport failed: {msg}")
            
    # ----------------------------------------------------------------------
    # (1b) Send a file to another machine using an explicit transport choice
    # ----------------------------------------------------------------------
    def _tool_send_file(self, ctx, path):
        self._discover_modules()
        ui = ctx.ui
        filename = os.path.basename(path)

        # Build a list of available send transports
        names = []
        funcs = []
        for mod in self.modules:
            if hasattr(mod, "provide_transfer"):
                try:
                    names.append(f"{mod.__name__}")
                    funcs.append((mod, mod.provide_transfer))
                except Exception:
                    pass

        if not names:
            return ui.show_message("No transit modules available for sending.")

        idx = ui.menu(title=f"Send '{filename}' using which transport?", items=names)
        if idx is None:
            return ui.show_message("Send cancelled.")

        mod, sendfn = funcs[idx]

        # Actually attempt to send the file
        try:
            ok, msg = sendfn(ctx, path)
        except Exception as e:
            return ui.show_message(f"{mod.__name__} failed: {e}")

        if ok:
            ui.show_message(f"Send succeeded: {msg}")
        else:
            ui.show_message(f"Send failed: {msg}")


    # ----------------------------------------------------------------------
    # (2) Provide a fallback “transfer_path” for Kitty integration
    # ----------------------------------------------------------------------
    def transfer_path_hook(self, ctx, path):
        """
        Called by the file manager when it wants to "transfer" a file via Kitty
        but Kitty support is unavailable. We try modules in order.
        Return (ok, message).
        """
        self._discover_modules()

        for mod in self.modules:
            if hasattr(mod, "provide_transfer"):
                try:
                    ok, msg = mod.provide_transfer(ctx, path)
                    if ok:
                        return ok, msg
                except Exception:
                    pass

        return False, "No transit modules could transfer this path."

    def _tool_transfer_path(self, ctx):
        """Interactive version of transfer_path_hook."""
        ui = ctx.ui
        self._discover_modules()
        chosen = self._teleportable_file(ctx)
        if not chosen:
            return ui.show_message("No file selected.")

        ok, msg = self.transfer_path_hook(ctx, chosen)
        if ok:
            ui.show_message(f"Transfer succeeded: {msg}")
        else:
            ui.show_message(f"Transfer failed: {msg}")


# --- import underlying transports ---
try:
    import scpback
except Exception:
    scpback = None

try:
    from path2wormhole import send_file as wormhole_send, receive_file as wormhole_recv
except Exception:
    wormhole_send = wormhole_recv = None

try:
    import rzsz1337modem
except Exception:
    rzsz1337modem = None

try:
    import fskradioroom
except Exception:
    fskradioroom = None


# -------------------------------------------------------
#   Utilities
# -------------------------------------------------------

def ask_ui_or_stdin(ctx, msg):
    ui = getattr(ctx, "ui", None)
    if ui:
        return ui.inbox(msg)
    return input(msg + ": ").strip()


# =======================================================
#   SCPBACK ADAPTER
# =======================================================

class SCPBackTransitModule:
    """
    Wrapper around scpback.py functionality.
    Provides terminal-OSC request, and falls back to SCP if needed.
    """

    def can_pull(self, ctx):
        return scpback is not None and shutil.which("scp") and shutil.which("ssh")

    def pull(self, ctx, remote_path, destdir):
        if scpback is None:
            return False, "scpback unavailable"

        ssh_target = getattr(ctx, "ssh_target", None)
        if not ssh_target:
            ssh_target = ask_ui_or_stdin(ctx, "SSH user@host")

        try:
            resolved = scpback.resolve_remote(ssh_target, remote_path)
        except Exception as e:
            return False, f"Failed resolve: {e}"

        dest = os.path.join(destdir, os.path.basename(resolved))
        try:
            subprocess.check_call(["scp", f"{ssh_target}:{resolved}", dest])
            return True, f"Copied {resolved} → {dest}"
        except Exception as e:
            return False, f"SCP pull failed: {e}"

    def provide_transfer(self, ctx, path):
        if scpback is None:
            return False, "scpback unavailable"

        ssh_target = getattr(ctx, "ssh_target", None)
        if not ssh_target:
            ssh_target = ask_ui_or_stdin(ctx, "SSH user@host")

        # try OSC-1337 request first
        try:
            ok, _ = scpback.request_via_pty([ssh_target], path, timeout=5)
            if ok:
                return True, "OSC1337 request sent."
        except Exception:
            pass

        # fallback: scp push
        try:
            subprocess.check_call(["scp", path, f"{ssh_target}:{os.path.basename(path)}"])
            return True, "Uploaded via SCP."
        except Exception as e:
            return False, f"SCP push failed: {e}"


# =======================================================
#   WORMHOLE ADAPTER
# =======================================================

class WormholeTransitModule:
    """
    Wrapper for path2wormhole.py
    """

    def can_pull(self, ctx):
        return wormhole_send is not None and shutil.which("wormhole")

    def pull(self, ctx, remote_path, destdir):
        if wormhole_recv is None:
            return False, "wormhole unavailable"

        code = ask_ui_or_stdin(ctx, f"Wormhole code for '{remote_path}'")
        if not code:
            return False, "No code entered"

        cwd = os.getcwd()
        os.chdir(destdir)
        try:
            rc = wormhole_recv(code)
        finally:
            os.chdir(cwd)

        if rc == 0:
            return True, f"Received → {destdir}"
        return False, f"wormhole receive rc={rc}"

    def provide_transfer(self, ctx, path):
        if wormhole_send is None:
            return False, "wormhole unavailable"

        try:
            rc = wormhole_send(path, use_qr=True, do_clip=True)
            if rc == 0:
                return True, "Sent via wormhole."
            return False, f"wormhole send rc={rc}"
        except Exception as e:
            return False, f"wormhole send error: {e}"


# =======================================================
#   OSC1337 TERMINAL MODEM ADAPTER
# =======================================================

class RZSZ1337TransitModule:
    """
    Wrapper around rzsz1337modem.py
    """

    def can_pull(self, ctx):
        return rzsz1337modem is not None and sys.stdout.isatty()

    def pull(self, ctx, remote_path, destdir):
        if rzsz1337modem is None:
            return False, "1337 modem unavailable"

        # send XFER-REQUEST escape sequence
        req = (
            b'\x1b]1337;XFER-REQUEST={"path":' +
            repr(remote_path).encode() +
            b"}\x07"
        )
        sys.stdout.buffer.write(req)
        sys.stdout.buffer.flush()

        # receive into destdir
        out = os.path.join(destdir, f"received_{int(time.time())}.bin")
        cwd = os.getcwd()
        os.chdir(destdir)
        try:
            rzsz1337modem.receive_stream(False)
        finally:
            os.chdir(cwd)

        return True, f"OSC1337 RX complete → {out}"

    def provide_transfer(self, ctx, path):
        if rzsz1337modem is None:
            return False, "1337 modem unavailable"
        if not os.path.exists(path):
            return False, "File does not exist"

        # announce IHAZ
        rzsz1337modem.emit_ihaz(path, sys.stdout.buffer.write)
        sys.stdout.buffer.flush()

        buf = bytearray()
        while True:
            chunk = sys.stdin.buffer.read1(4096)
            if not chunk:
                break
            buf.extend(chunk)

            m = rzsz1337modem.OSC_PATTERN.search(buf)
            if not m:
                continue

            if m.group(1) == b"XFER-IHAZBELLY":
                rzsz1337modem.send_file(path, False, sys.stdout.buffer.write)
                return True, "1337 send complete"

        return False, "Remote never sent IHAZBELLY"


# =======================================================
#   FSK RADIO ROOM ADAPTER
# =======================================================

class FSKRadioTransitModule:
    """
    Wrapper around fskradioroom.py (acoustic modem)
    """

    def can_pull(self, ctx):
        try:
            import pyaudio
            pyaudio.PyAudio().terminate()
            return True
        except Exception:
            return False

    def pull(self, ctx, remote_path, destdir):
        if fskradioroom is None:
            return False, "fskradioroom unavailable"

        out = os.path.join(destdir, f"received_{int(time.time())}.bin")

        ui = getattr(ctx, "ui", None)
        if ui:
            ui.show_message(f"Prepare remote to send '{remote_path}' over audio.")

        ok = fskradioroom.receive_listen(out_path=out)
        if ok:
            return True, f"Audio packet received → {out}"
        return False, "No valid FSK packet heard."

    def provide_transfer(self, ctx, path):
        if fskradioroom is None:
            return False, "fskradioroom unavailable"
        if not os.path.exists(path):
            return False, "File does not exist"

        try:
            fskradioroom.send_file(path)
            return True, "Audio send complete"
        except Exception as e:
            return False, f"Audio send error: {e}"


# =======================================================
#   THE HUB
# =======================================================

class NotalsTransitHubHub:
    """
    Collects all transit modules and picks working ones.
    Tries transports in a context-aware order.
    """

    def __init__(self):
        self.modules = self._ordered_modules()

    # ----------------------------------------------------------------------
    # Adaptive module ordering
    # ----------------------------------------------------------------------
    def _ordered_modules(self):
        """
        Choose module order based on available environment.
        Prefers:
            1. RZSZ1337 (OSC modem) if TTY detected
            2. SCPBack (SSH/SCP binaries available)
            3. Wormhole (if installed)
            4. FSK Radio (if pyaudio available)
        """
        mods = []

        # TTY-based OSC modem
        if sys.stdout.isatty():
            mods.append(RZSZ1337TransitModule())

        # SSH/SCP availability
        if shutil.which("scp") and shutil.which("ssh"):
            mods.append(SCPBackTransitModule())

        # Wormhole if installed
        if shutil.which("wormhole"):
            mods.append(WormholeTransitModule())

        # Acoustic fallback
        try:
            import pyaudio
            pyaudio.PyAudio().terminate()
            mods.append(FSKRadioTransitModule())
        except Exception:
            pass

        # Fallback: if none detected, still return all in safe order
        if not mods:
            mods = [
                RZSZ1337TransitModule(),
                SCPBackTransitModule(),
                WormholeTransitModule(),
                FSKRadioTransitModule(),
            ]

        return mods

    # ----------------------------------------------------------------------
    # Pull / push handling
    # ----------------------------------------------------------------------
    def available_pullers(self, ctx):
        return [m for m in self.modules if hasattr(m, "can_pull") and m.can_pull(ctx)]

    def try_pull(self, ctx, remote_path, destdir):
        for m in self.available_pullers(ctx):
            ok, msg = m.pull(ctx, remote_path, destdir)
            if ok:
                return ok, msg
        return False, "All pull methods failed"

    def provide_transfer(self, ctx, path):
        for m in self.modules:
            ok, msg = m.provide_transfer(ctx, path)
            if ok:
                return ok, msg
        return False, "All transfer methods failed"



class TeleportReceiveTool(ThingToolsTool):
    """Receive a file from a remote host via any available transport."""
    def __init__(self, hub, chosen):
        self.label = f"Teleport file (receive): {os.path.basename(chosen)}"
        self.hotkey = None
        self.description = "Pull a file from a remote system using one of the available transports."
        self._hub = hub
        self._chosen = chosen

    def safe_run(self, ctx):
        self._hub._tool_teleport_file(ctx, self._chosen)

    def enabled(self, ctx):
        return True
        
class SendFileTool(ThingToolsTool):
    """Send the selected file using a chosen transport method."""
    def __init__(self, hub, chosen):
        self.label = f"Send file (choose transport): {os.path.basename(chosen)}"
        self.hotkey = None
        self.description = "Push the selected file using one of the configured transports."
        self._hub = hub
        self._chosen = chosen

    def safe_run(self, ctx):
        self._hub._tool_send_file(ctx, self._chosen)

    def enabled(self, ctx):
        return True
        
class AutoTransferTool(ThingToolsTool):
    """Automatically transfer the current path using best available method."""
    label = "Transfer path using best available transport"
    hotkey = None
    description = "Try each available transport until one succeeds."

    def __init__(self, hub):
        self._hub = hub

    def safe_run(self, ctx):
        self._hub._tool_transfer_path(ctx)

    def enabled(self, ctx):
        return True
        
class OpenTransitHubTool(ThingToolsTool):
    label = "Open Transit Hub"
    hotkey = "t"
    def run(self, ctx):
        ctx.ui.show_message("Transit Hub ready – select a file to send/receive.")

