#!/usr/bin/env python3
# notals.py (not-a-ls -- it's not nautilus & it's not ls!)
# Warning: Very experimental file manager esp on mounts - run only in ephemeral Docker containers or VM you expect to lose!

import curses, copy, atexit, json, os, mimetypes, shutil, subprocess, zipfile, tarfile
import pwd, grp, datetime, hashlib, time, pathlib
from functools import lru_cache
import shlex
#
# Logging location:
#   If NOTALS_LOG_HERE=1, log in the invoking directory.
#   Otherwise, use XDG_STATE_HOME or ~/.local/state/notals/
#

TRASH_DIR = os.path.expanduser("~/.local/share/notals_trash")
os.makedirs(TRASH_DIR, exist_ok=True)

def move_to_trash(stdscr, srcp, name, set_status):
    # Use safer move so undo history is preserved
    ok = safer_move_or_copy(stdscr, srcp, name, TRASH_DIR, "move")
    if ok:
        set_status(f"[Trash] {name} → ~/.local/share/notals_trash/")
    else:
        set_status(f"[Failed] Could not move {name} to trash")



if os.environ.get("NOTALS_LOG_HERE") == "1":
    LOG_FILE = "notals_movelog.log"
else:
    state_home = os.environ.get("XDG_STATE_HOME",
                                os.path.expanduser("~/.local/state"))
    log_dir = os.path.join(state_home, "notals")
    pathlib.Path(log_dir).mkdir(parents=True, exist_ok=True)
    LOG_FILE = os.path.join(log_dir, "movelog.log")

PROJECT_TYPES = {
    "docker":  {"icon": "🐳"},
    "k8s":     {"icon": "☸️"},
    "rn":      {"icon": "⚛️📱"},
    "flutter": {"icon": "🦋"},
    "node":    {"icon": "📦"},
    "rust":    {"icon": "🦀"},
    "go":      {"icon": "🐹"},
    "python":  {"icon": "🐍"},
    "git":     {"icon": ""},
}

import curses, os


def chdir(path, statusLambda= lambda fmtStr: 0 ):
    try:
        os.chdir(path)
    except PermissionError:
        statusLambda("🚫 No permission to enter: {}".format(path))
        return -1
    except FileNotFoundError:
        statusLambda("❓ Directory disappeared: {}".format(path))
        return -1 
    except NotADirectoryError:
        statusLambda("This isn’t a directory.")
        return -1
    return 0

def is_barging(path):
    return not (os.path.isdir(path) and os.access(path, os.X_OK) and os.access(path, os.R_OK))


# 3 Systems for Action in not-a-ls
# 1. Thing tools (from a folder-level Tools menu, needn't have much to do with the folder
# 2. Project/Special Folder Specific Actions menu, folder scoped based on the tags of the folder
# 3. Smart filetype preview actions
import time
from collections import defaultdict

TOOL_PROF = defaultdict(lambda: {"detect": 0.0, "tools": 0.0})


class ThingTools:
    """
    A collection of related tool actions.

    Each subclass should:
      - Provide a `name` describing the group.
      - Optionally override `detect` to control visibility.
      - Return ThingToolsTool instances from `tools(context)`.

    Examples include GitTools, DockerTools, AudioTools, etc.
    """
    name = "Generic"
    priority = 50  # Lower = appears earlier in menus

    def detect(self, cwd, system_info):
        """
        Return True if this tool group should be shown in the menu.
        """
        return True

    def tools(self, context):
        """
        Return a list of ThingToolsTool instances.
        Override in subclasses.
        """
        return []
        
    @staticmethod
    def gather_tools(context, tool_groups):
        tool_entries = []

        for group_cls in tool_groups:
            group = group_cls()

            # --- measure detect() ---
            t0 = time.time()
            ok = group.detect(context.cwd, context.system_info)
            TOOL_PROF[group_cls.__name__]["detect"] += (time.time() - t0)

            if not ok:
                continue

            # --- measure tools() ---
            t1 = time.time()
            tools_list = group.tools(context)
            TOOL_PROF[group_cls.__name__]["tools"] += (time.time() - t1)

            for tool in tools_list:
                if tool.enabled(context):
                    label = tool.label
                    hk = tool.hotkey
                    tool_entries.append((group.priority, hk, label, tool))

        tool_entries.sort(key=lambda x: (x[0], x[1] or x[2]))
        return [(hk, label, tool) for _, hk, label, tool in tool_entries]





@lru_cache(maxsize=1)
def all_thingtools_classes():
    """
    Collect ThingTools subclasses and optionally extend with extras
    when NOTALS_XTRAS is truthsome in the environment.
    """

    found = set()

    def collect(cls):
        for sub in cls.__subclasses__():
            found.add(sub)
            collect(sub)

    collect(ThingTools)

    if os.environ.get("NOTALS_XTRAS", "").strip().lower() not in ("", "0", "false", "no"):
        try:
            from notals_xtras import EXTRA_TOOLS
            for tool in EXTRA_TOOLS:
                found.add(tool)
        except Exception as exc:
           
            print(f"[notals] WARN: NOTALS_XTRAS enabled but extras failed to load: {exc}")


    return sorted(found, key=lambda c: getattr(c, "priority", 50))


class ThingToolsTool:
    """
    Represents a single actionable operation.

    Tools may define:
      - label (displayed to the user)
      - hotkey (optional keyboard shortcut)
      - description (optional help text shown in help pane)
      - enabled(context) to dynamically control availability

    The `run(context)` method performs the operation.
    """
    label = "Unnamed Tool"
    description = None
    hotkey = None   # single-character accelerator, optional

    def enabled(self, context):
        """
        Return whether this tool should be selectable in the menu.
        Override if availability depends on context.
        """
        return True

    def safe_run(self, context):
        """
        Wrapper around run() to ensure the UI is not left corrupted
        if an exception occurs.
        """
        try:
            return self.run(context)
        except Exception as e:
            context.notify(f"Error: {e}")

    def run(self, context):
        raise NotImplementedError


import subprocess, shutil, os, curses

class ThingToolsToolContext:
    """
    Operates as the execution environment for tool actions.
    """
    def __init__(self, ui, cwd, selected_file, selected_files, system_info, clipboard):
        self.ui = ui
        self.cwd = cwd
        self.selected_file = selected_file
        self.selected_files = selected_files or []
        self.system_info = system_info
        self.clipboard = clipboard

    # --- UI wrappers ---
    def notify(self, msg):
        self.ui.show_message(msg)

    def confirm(self, question):
        return self.ui.confirm_dialog(question)

    def input_prompt(self, prompt):
        return self.ui.input_dialog(prompt)

    def text_preview(self, text, title="Preview"):
        return self.ui.text_preview_dialog(text, title)

    def list_menu(self, items, title="Menu"):
        return self.ui.list_menu_dialog(items, title)

    # --- curses state control ---
    def end_curses(self):
        curses.endwin()

    def restore_curses(self):
        self.ui.redraw()

    # --- command helpers ---
    def shell(self, cmd, pager=False):
        if pager:
            return self.run_command_pager(cmd)
        return self.run_command_preview(cmd)

    def run_command_preview(self, cmd):
        output = subprocess.getoutput(cmd)
        self.text_preview(output, title=cmd)

    def run_command_pager(self, cmd):
        self.end_curses()
        try:
            subprocess.run(cmd, shell=True)
        finally:
            self.restore_curses()

    def run_interactive(self, cmd):
        self.end_curses()
        try:
            subprocess.run(cmd, shell=True)
        finally:
            self.restore_curses()

    def call(self, binary, *args):
        self.end_curses()
        try:
            subprocess.run([binary, *args])
        finally:
            self.restore_curses()

    def which_available(self, binaries):
        for b in binaries:
            if shutil.which(b):
                return b
        return None

    # --- filesystem ---
    def open_file(self, path):
        self.ui.open_file_editor(path)

    def move_file(self, src, dst):
        self.ui.fs_move(src, dst)

    def copy_file(self, src, dst):
        self.ui.fs_copy(src, dst)

    def trash_file(self, path):
        self.ui.fs_trash(path)

    def mkdir(self, path):
        os.makedirs(path, exist_ok=True)
        
        

def show_tools_menu(ui):
    context = ThingToolsToolContext(
        ui=ui,
        cwd=ui.current_directory,
        selected_file=ui.get_selected_file(),
        selected_files=ui.get_selected_files(),
        system_info=ui.system_info,
        clipboard=ui.clipboard
    )

    tool_classes = all_thingtools_classes()
    tools = ThingTools.gather_tools(context, tool_classes)
    # tools looks like: [(hotkey, label, toolobj), ...]

    # Build display labels for menu:
    items = [
        (f"[{hk}] {label}" if hk else label)
        for (hk, label, tool) in tools
    ]

    choice = ui.list_menu_dialog(items, "Tools")
    if choice is None:
        return

    hk, label, tool = tools[choice]
    tool.safe_run(context)

        

class AsciinemaTools(ThingTools):
    name = "Asciinema"
    priority = 35  # appears fairly early but below Git/Docker/etc.

    def detect(self, cwd, system_info):
        # Only show this tool section if asciinema is installed
        return shutil.which("asciinema") is not None

    def tools(self, context):
        return [
            AsciinemaRecordTool(),
            AsciinemaReplayTool(),
        ]


class AsciinemaRecordTool(ThingToolsTool):
    label = "Record Terminal Session"
    hotkey = "r"
    description = "Start an asciinema recording and save it to a .cast file."

    def run(self, context):
        # ask where to save
        fname = context.input_prompt("Save to (default: session.cast):")
        if not fname:
            fname = "session.cast"
        fname = os.path.join(context.cwd, fname)

        context.notify(f"Recording… (Ctrl-D or exit to stop)")
        context.run_interactive(f"asciinema rec {shlex.quote(fname)}")
        context.notify(f"Saved: {fname}")


class AsciinemaReplayTool(ThingToolsTool):
    label = "Replay Recording"
    hotkey = "p"
    description = "Select a .cast file in this directory and replay it."

    def enabled(self, context):
        # enable only if there is at least one .cast file in cwd
        return any(f.endswith(".cast") for f in os.listdir(context.cwd))

    def run(self, context):
        cast_files = [f for f in os.listdir(context.cwd) if f.endswith(".cast")]
        if not cast_files:
            context.notify("No .cast files found.")
            return

        choice = context.list_menu(cast_files, title="Select recording to replay:")
        if not choice:
            return

        target = os.path.join(context.cwd, choice)
        context.run_interactive(f"asciinema play {shlex.quote(target)}")
        


class DumbEd():
    def __init__(self, stdscr, path):
        self.stdscr = stdscr
        self.path = path
        self.lines = self.load_file()
        self.cursor_y = 0
        self.cursor_x = 0
        self.scroll = 0
        self.dirty = False
        self.undo_stack = []
        self.message = ""
        self.search_query = None
        self.quit_armed = False


    def load_file(self):
        if not os.path.exists(self.path):
            return [""]  # new empty buffer

        with open(self.path, "r", errors="replace") as f:
            lines = f.read().splitlines()
        if not lines:
            lines = [""]  # ensure at least one line
        return lines

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            f.write("\n".join(self.lines))
        os.replace(tmp, self.path)
        self.dirty = False
        self.message = "[Saved]"

    def snapshot(self):
        # for undo
        self.undo_stack.append((self.lines[:], self.cursor_y, self.cursor_x))

    def undo(self):
        if not self.undo_stack:
            self.message = "[Nothing to undo]"
            return
        self.lines, self.cursor_y, self.cursor_x = self.undo_stack.pop()
        self.dirty = True
        self.message = "[Undo]"

    def run(self):
        curses.curs_set(1)
        while True:
            self.draw()
            ch = self.stdscr.getch()
            if not self.handle_key(ch):
                break
        curses.curs_set(0)

    def handle_key(self, ch):
        # --- Quit (double Ctrl-Q) ---
        if ch == 17:  # Ctrl-Q
            if not self.quit_armed:
                self.message = "[Press Ctrl-Q again to quit]"
                self.quit_armed = True
                return True
            # second Ctrl-Q
            if self.dirty:
                if not self.confirm("Unsaved changes. Quit? (y/n)"):
                    self.quit_armed = False
                    return True
            return False  # <-- only exit point

        # reset quit arm if any other key is pressed
        self.quit_armed = False

        # --- Save ---
        if ch == 19:  # Ctrl-S
            self.save()
            return True

        # --- Undo ---
        if ch == 26:  # Ctrl-Z
            self.undo()
            return True

        # --- Search ---
        if ch == 6:  # Ctrl-F
            self.search_prompt()
            return True

        # --- Movement ---
        if ch == curses.KEY_UP:
            self.cursor_y = max(0, self.cursor_y - 1)
            return True
        if ch == curses.KEY_DOWN:
            self.cursor_y = min(len(self.lines) - 1, self.cursor_y + 1)
            return True
        if ch == curses.KEY_LEFT:
            self.cursor_x = max(0, self.cursor_x - 1)
            return True
        if ch == curses.KEY_RIGHT:
            self.cursor_x = min(len(self.lines[self.cursor_y]), self.cursor_x + 1)
            return True
        if ch == curses.KEY_HOME:
            self.cursor_x = 0
            return True
        if ch == curses.KEY_END:
            self.cursor_x = len(self.lines[self.cursor_y])
            return True
        if ch == curses.KEY_NPAGE:
            self.cursor_y = min(len(self.lines)-1, self.cursor_y + 10)
            return True
        if ch == curses.KEY_PPAGE:
            self.cursor_y = max(0, self.cursor_y - 10)
            return True

        # --- Backspace / Delete ---
        if ch in (curses.KEY_BACKSPACE, 127, 8):
            self.backspace()
            return True
        if ch == curses.KEY_DC:
            self.delete_char()
            return True

        # --- Enter ---
        if ch in (10, 13):
            self.newline()
            return True

        # --- Insert printable characters ---
        if 32 <= ch <= 126 or ch >= 128:
            self.insert_char(chr(ch))
            return True

        # --- Default: ignore key, stay open ---
        return True


    def insert_char(self, c):
        self.snapshot()
        line = self.lines[self.cursor_y]
        self.lines[self.cursor_y] = line[:self.cursor_x] + c + line[self.cursor_x:]
        self.cursor_x += 1
        self.dirty = True

    def backspace(self):
        if self.cursor_x == 0:
            if self.cursor_y == 0:
                return
            self.snapshot()
            # merge line with previous
            prev_len = len(self.lines[self.cursor_y - 1])
            self.lines[self.cursor_y - 1] += self.lines[self.cursor_y]
            del self.lines[self.cursor_y]
            self.cursor_y -= 1
            self.cursor_x = prev_len
            self.dirty = True
        else:
            self.snapshot()
            line = self.lines[self.cursor_y]
            self.lines[self.cursor_y] = line[:self.cursor_x - 1] + line[self.cursor_x:]
            self.cursor_x -= 1
            self.dirty = True

    def delete_char(self):
        line = self.lines[self.cursor_y]
        if self.cursor_x < len(line):
            self.snapshot()
            self.lines[self.cursor_y] = line[:self.cursor_x] + line[self.cursor_y][self.cursor_x+1:]
            self.dirty = True
        else:
            # join with next line
            if self.cursor_y < len(self.lines)-1:
                self.snapshot()
                self.lines[self.cursor_y] += self.lines[self.cursor_y+1]
                del self.lines[self.cursor_y+1]
                self.dirty = True

    def newline(self):
        self.snapshot()
        line = self.lines[self.cursor_y]
        self.lines[self.cursor_y] = line[:self.cursor_x]
        self.lines.insert(self.cursor_y+1, line[self.cursor_x:])
        self.cursor_y += 1
        self.cursor_x = 0
        self.dirty = True

    def search_prompt(self):
        curses.echo()
        self.stdscr.addstr(curses.LINES-1, 0, "Search: ")
        query = self.stdscr.getstr().decode("utf-8")
        curses.noecho()
        if not query:
            return
        self.search_query = query
        for i, line in enumerate(self.lines):
            pos = line.find(query)
            if pos != -1:
                self.cursor_y = i
                self.cursor_x = pos
                self.message = f"[Found '{query}']"
                return
        self.message = f"[Not found: {query}]"

    def confirm(self, msg):
        self.stdscr.addstr(curses.LINES-1, 0, msg + " ")
        self.stdscr.clrtoeol()
        self.stdscr.refresh()
        c = self.stdscr.getch()
        return c in (ord("y"), ord("Y"))

    def draw(self):
        h, w = self.stdscr.getmaxyx()
        view_h = h - 3   # one header + one status + one message line

        # ensure scroll position
        if self.cursor_y < self.scroll:
            self.scroll = self.cursor_y
        if self.cursor_y >= self.scroll + view_h:
            self.scroll = self.cursor_y - view_h + 1

        self.stdscr.erase()

        # --- HEADER BAR ---
        header = f" DumbEd — {self.path} "
        self.stdscr.addstr(0, 0, header[:w-1], curses.A_REVERSE)

        # --- TEXT CONTENT ---
        for i in range(view_h):
            idx = self.scroll + i
            if idx < len(self.lines):
                line = self.lines[idx]
                self.stdscr.addstr(1 + i, 0, line[:w-1])

        # --- STATUS / MESSAGE ---
        status = f"{'*' if self.dirty else ' '}"
        pos = f"  ln {self.cursor_y+1}, col {self.cursor_x+1}"
        self.stdscr.addstr(h-2, 0, (status + pos)[:w-1], curses.A_DIM)

        if self.message:
            self.stdscr.addstr(h-1, 0, self.message[:w-1], curses.A_BOLD)
        else:
            helpbar = " Ctrl-S save | Ctrl-Q quit | Ctrl-Z undo | Ctrl-F search "
            self.stdscr.addstr(h-1, 0, helpbar[:w-1], curses.A_DIM)

        self.stdscr.move(1 + self.cursor_y - self.scroll, self.cursor_x)
        self.stdscr.refresh()

        
class OpenInDumbEdTool(ThingToolsTool):
    label = "Edit (DumbEd)"
    hotkey = "e"

    def run(self, context):
        editor = DumbEd(context.ui.stdscr, context.selected_file)
        editor.run()
        
class TextEditingTools(ThingTools):
    name = "Text Editing"
    priority = 45  # near Git, Docker, etc.

    def detect(self, cwd, system_info):
        # Only show if a selected file is text-like
        sel = system_info.get("selected_file_fullpath") if hasattr(system_info, "get") else None
        return True  # keep simple; tool.enable() will filter

    def tools(self, context):
        # Only show DumbEd option if a file is selected and writable
        if context.selected_file and os.path.isfile(os.path.join(context.cwd, context.selected_file)):
            return [OpenInDumbEdTool()]
        return []



import os, json, subprocess, shutil

class KubernetesDebugTools:
    def __init__(self):
        self.ns_path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
        self.token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        self.ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

        self.namespace = self._read_file(self.ns_path)
        self.pod_name = os.environ.get("HOSTNAME", "?")
        self.node_name = self._read_file("/etc/hostname")
        self.apiserver = self._detect_apiserver()
        self.token = self._read_file(self.token_path)

        self.kubectl_ok = self._has_kubectl_access()

    # ---------- internal utilities ----------
    def _read_file(self, path):
        try:
            with open(path) as f:
                return f.read().strip()
        except:
            return None

    def _detect_apiserver(self):
        host = os.environ.get("KUBERNETES_SERVICE_HOST")
        port = os.environ.get("KUBERNETES_PORT_443_TCP_PORT", "443")
        return f"https://{host}:{port}" if host else None

    def _curl_api(self, path):
        if not (self.token and self.apiserver):
            return None
        cmd = [
            "curl", "--silent", "--fail",
            "--cacert", self.ca_path,
            "-H", f"Authorization: Bearer {self.token}",
            "-H", "Accept: application/json",
            self.apiserver + path
        ]
        return subprocess.run(cmd, capture_output=True, text=True).stdout

    def _has_kubectl_access(self):
        if shutil.which("kubectl") is None:
            return False
        test = subprocess.run(
            ["kubectl", "auth", "can-i", "get", "pods"],
            capture_output=True, text=True
        )
        return "yes" in test.stdout.lower()

    # ---------- Tier 0: Always works ----------
    def pod_identity(self):
        return {
            "pod": self.pod_name,
            "namespace": self.namespace,
            "node": self.node_name
        }

    def list_mounts(self):
        try:
            return open("/proc/mounts").read()
        except:
            return "[no mount info]"

    def dns_lookup(self, name):
        return subprocess.run(["nslookup", name],
                              capture_output=True, text=True).stdout

    # ---------- Tier 1: API direct queries (no kubectl needed) ----------
    def pod_json(self):
        if not self.apiserver:
            return "[No API server detected]"
        raw = self._curl_api(f"/api/v1/namespaces/{self.namespace}/pods/{self.pod_name}")
        try:
            return json.loads(raw)
        except:
            return raw or "[No response]"

    def list_pods_in_namespace(self):
        raw = self._curl_api(f"/api/v1/namespaces/{self.namespace}/pods")
        if not raw:
            return "[No permission or API not accessible]"
        try:
            data = json.loads(raw)
            return [i["metadata"]["name"] for i in data.get("items", [])]
        except:
            return raw

    # ---------- Tier 2: kubectl-only safe operations ----------
    def exec_into_container(self, container_name=None):
        if not self.kubectl_ok:
            return "[kubectl not permitted or missing]"
        if not container_name:
            pod = self.pod_json()
            containers = [c["name"] for c in pod["spec"]["containers"]]
            container_name = containers[0]  # or integrate UI selection
        subprocess.run(["kubectl", "-n", self.namespace,
                        "exec", "-it", self.pod_name,
                        "-c", container_name, "--", "sh"])
        return "[exec finished]"

    def tail_logs(self, container_name=None):
        if not self.kubectl_ok:
            return "[kubectl not permitted or missing]"
        cmd = ["kubectl", "-n", self.namespace, "logs", "-f", self.pod_name]
        if container_name:
            cmd += ["-c", container_name]
        subprocess.run(cmd)
        return "[log tail ended]"
        
        
class KubeIdentityTool(ThingToolsTool):
    label = "K8s: Show Pod Identity"
    hotkey = "i"

    def run(self, context):
        k = KubernetesDebugTools()
        info = k.pod_identity()
        context.ui.popup_message(
            f"Pod: {info['pod']}\n"
            f"Namespace: {info['namespace']}\n"
            f"Node: {info['node']}"
        )

class KubeListPodsTool(ThingToolsTool):
    label = "K8s: List Pods in Namespace"
    hotkey = "p"

    def run(self, context):
        k = KubernetesDebugTools()
        pods = k.list_pods_in_namespace()
        if isinstance(pods, list):
            text = "\n".join(pods)
        else:
            text = str(pods)
        context.ui.popup_message(text)

class KubeLogsTool(ThingToolsTool):
    label = "K8s: Tail Logs"
    hotkey = "l"

    def run(self, context):
        k = KubernetesDebugTools()
        k.tail_logs()  # interactive call, UI resumes afterward

class KubeExecTool(ThingToolsTool):
    label = "K8s: Shell Into Container"
    hotkey = "s"

    def run(self, context):
        k = KubernetesDebugTools()
        k.exec_into_container()


class KubernetesTools(ThingTools):
    name = "Kubernetes"
    priority = 60  # appears near Docker, Git, etc.

    def detect(self, cwd, system_info):
        # Show only if this system is in a pod AND can actually talk to the API
        k = KubernetesDebugTools()
        return bool(k.namespace) and bool(k.apiserver)

    def tools(self, context):
        return [
            KubeIdentityTool(),
            KubeListPodsTool(),
            KubeLogsTool(),
            KubeExecTool()
        ]



class DockerContainedDebugTools:
    """
    Tools available when running *inside* a Docker container.
    Detects container ID, image, mounts, networks, and offers interactive debugging actions.
    """

    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.container_id = self._detect_container_id()
        self.inspected = self._inspect_container() if self.container_id else None

    def _shell(self, cmd):
        # Safely leave curses, run interactive commands, return
        curses.endwin()
        try:
            subprocess.run(cmd, shell=isinstance(cmd, str))
        finally:
            try:
                curses.doupdate()
            except:
                pass

    def _detect_container_id(self):
        try:
            out = subprocess.check_output(
                "cat /proc/self/cgroup | head -n1 | awk -F/ '{print $NF}'",
                shell=True, text=True
            ).strip()
            return out if out else None
        except:
            return None

    def _inspect_container(self):
        try:
            data = subprocess.check_output(
                ["docker", "inspect", self.container_id],
                text=True
            )
            return json.loads(data)[0]
        except:
            return None

    # --------------------- Actions ---------------------

    def inspect_container(self):
        if not self.inspected:
            return
        text = json.dumps(self.inspected, indent=2)
        text_preview_dialog(self.stdscr, "Container Inspect", text)

    def view_mounts(self):
        if not self.inspected:
            return
        mounts = self.inspected.get("Mounts", [])
        text = "\n".join(f"{m['Source']} -> {m['Destination']}" for m in mounts)
        text_preview_dialog(self.stdscr, "Mounts", text or "(none)")

    def view_ports(self):
        if not self.inspected:
            return
        ports = self.inspected.get("NetworkSettings", {}).get("Ports", {})
        text = "\n".join(f"{k} -> {v}" for k, v in ports.items())
        text_preview_dialog(self.stdscr, "Ports", text or "(none)")

    def list_containers(self):
        self._shell("docker ps")

    def exec_into_container(self):
        # Ask user for a container name/id
        target = path_input_dialog(self.stdscr, "Container to enter:")
        if target:
            self._shell(f"docker exec -it {shlex.quote(target)} /bin/sh")

    def tail_logs(self):
        target = path_input_dialog(self.stdscr, "Container logs for:")
        if target:
            self._shell(f"docker logs -f {shlex.quote(target)}")

    def restart_container(self):
        self._shell(f"docker restart {self.container_id}")

    def snapshot_container(self):
        name = path_input_dialog(self.stdscr, "Snapshot image name:")
        if name:
            self._shell(f"docker commit {self.container_id} {shlex.quote(name)}")

    def try_host_fs(self):
        # Heuristics for host mounts
        candidates = ["/host", "/mnt/host", "/run/host"]
        for c in candidates:
            if os.path.isdir(c):
                new_path = c
                path_input_dialog(self.stdscr, f"Host fs likely at {new_path}")
                return
        text_preview_dialog(self.stdscr, "Host FS", "No known host mount found.")

    # --------------------- UI Menu ---------------------

    def run(self):
        menu = [
            ("Inspect Container", self.inspect_container),
            ("View Mounts / Volumes", self.view_mounts),
            ("View Port Mappings", self.view_ports),
            ("Network Scan", self.network_scan),
            ("List Running Containers", self.list_containers),
            ("Exec Into Another Container", self.exec_into_container),
            ("Tail Container Logs", self.tail_logs),
            ("nsenter Into Another Container", self.nsenter_other_container),
            ("nsenter Into Host (if permitted)", self.nsenter_host),
            ("Probe Network Port", self.port_probe),
            ("Snapshot This Container", self.snapshot_container),
            ("Restart This Container", self.restart_container),
            ("Try Host Filesystem Access", self.try_host_fs),
        ]


        sel = 0
        while True:
            self.stdscr.erase()
            self.stdscr.box()
            self.stdscr.addstr(1, 2, f"Docker Container Debug Tools", curses.A_BOLD)
            for i, (label, _) in enumerate(menu):
                style = curses.A_REVERSE if i == sel else curses.A_NORMAL
                self.stdscr.addstr(3 + i, 4, label, style)
            self.stdscr.refresh()

            ch = self.stdscr.getch()
            if ch in (ord("q"), 27):
                return
            elif ch == curses.KEY_UP:
                sel = max(0, sel - 1)
            elif ch == curses.KEY_DOWN:
                sel = min(len(menu) - 1, sel + 1)
            elif ch in (10, 13):
                menu[sel][1]()

    # --------------------- New Tools (2, 3, 4) ---------------------

    def network_scan(self):
        # Show interface + routing + listening sockets
        text = []

        def grab(cmd):
            try:
                return subprocess.check_output(cmd, shell=True, text=True)
            except:
                return f"[Failed] {cmd}\n"

        text.append("=== Interfaces (ip a) ===\n")
        text.append(grab("ip a"))
        text.append("\n=== Routes (ip route) ===\n")
        text.append(grab("ip route"))
        text.append("\n=== Listening Services (ss -tulpn) ===\n")
        text.append(grab("ss -tulpn || netstat -tulpn || lsof -i"))
        text.append("\n=== DNS Resolver (/etc/resolv.conf) ===\n")
        try:
            with open("/etc/resolv.conf") as f:
                text.append(f.read())
        except:
            text.append("[Could not read /etc/resolv.conf]\n")

        text_preview_dialog(self.stdscr, "Network Scan", "".join(text))

    def _select_running_container(self):
        try:
            out = subprocess.check_output(
                "docker ps --format '{{.ID}} {{.Names}}'",
                shell=True, text=True
            ).strip().splitlines()
        except:
            return None

        if not out:
            text_preview_dialog(self.stdscr, "Containers", "(none running)")
            return None

        entries = [line.split(maxsplit=1) for line in out]
        labels = [name for _, name in entries]

        sel = 0
        rows, cols = self.stdscr.getmaxyx()
        win = curses.newwin(len(labels)+4, max(len(max(labels, key=len))+6, 20),
                            (rows - (len(labels)+4))//2,
                            (cols - (len(max(labels, key=len))+6))//2)
        win.keypad(True)

        while True:
            win.erase()
            win.box()
            win.addstr(1, 2, "Select Container", curses.A_BOLD)
            for i, name in enumerate(labels):
                style = curses.A_REVERSE if i == sel else curses.A_NORMAL
                win.addstr(3+i, 2, name, style)
            win.refresh()

            ch = win.getch()
            if ch in (27, ord('q')):
                return None
            elif ch == curses.KEY_UP:
                sel = max(0, sel-1)
            elif ch == curses.KEY_DOWN:
                sel = min(len(labels)-1, sel+1)
            elif ch in (10, 13):
                return entries[sel][0]  # return container ID

    def nsenter_other_container(self):
        target = self._select_running_container()
        if not target:
            return
        # obtain PID
        try:
            pid = subprocess.check_output(
                f"docker inspect --format '{{{{.State.Pid}}}}' {shlex.quote(target)}",
                shell=True, text=True
            ).strip()
        except:
            return
        self._shell(f"nsenter --target {pid} --mount --uts --ipc --net --pid")

    def nsenter_host(self):
        # host PID is always 1 within container when privileged with host namespaces shared
        self._shell("nsenter --target 1 --mount --uts --ipc --net --pid")

    def port_probe(self):
        host = path_input_dialog(self.stdscr, "Host/IP to probe:")
        if not host:
            return
        port = path_input_dialog(self.stdscr, "Port to probe:")
        if not port:
            return

        test_commands = [
            f"timeout 3 nc -vz {shlex.quote(host)} {shlex.quote(port)}",
            f"timeout 3 curl -v http://{shlex.quote(host)}:{shlex.quote(port)}",
            f"timeout 3 curl -v https://{shlex.quote(host)}:{shlex.quote(port)}",
        ]

        curses.endwin()
        print(f"=== Probing {host}:{port} ===")
        for cmd in test_commands:
            print(f"\n--- {cmd} ---")
            subprocess.run(cmd, shell=True)
        input("\nPress Enter to return...")
        curses.doupdate()
        

class DockerInspectTool(ThingToolsTool):
    label = "Docker: Inspect This Container"
    hotkey = "i"

    def run(self, context):
        d = DockerContainedDebugTools(context.ui.stdscr)
        d.inspect_container()

class DockerViewMountsTool(ThingToolsTool):
    label = "Docker: View Mounts"
    hotkey = "m"

    def run(self, context):
        d = DockerContainedDebugTools(context.ui.stdscr)
        d.view_mounts()

class DockerViewPortsTool(ThingToolsTool):
    label = "Docker: View Port Mappings"
    hotkey = "p"

    def run(self, context):
        d = DockerContainedDebugTools(context.ui.stdscr)
        d.view_ports()

class DockerExecOtherTool(ThingToolsTool):
    label = "Docker: Exec Into Another Container"
    hotkey = "e"

    def run(self, context):
        d = DockerContainedDebugTools(context.ui.stdscr)
        d.exec_into_container()

class DockerLogsTool(ThingToolsTool):
    label = "Docker: Tail Container Logs"
    hotkey = "l"

    def run(self, context):
        d = DockerContainedDebugTools(context.ui.stdscr)
        d.tail_logs()

class DockerRestartTool(ThingToolsTool):
    label = "Docker: Restart This Container"
    hotkey = "r"

    def run(self, context):
        d = DockerContainedDebugTools(context.ui.stdscr)
        d.restart_container()

class DockerSnapshotTool(ThingToolsTool):
    label = "Docker: Snapshot This Container"
    hotkey = "s"

    def run(self, context):
        d = DockerContainedDebugTools(context.ui.stdscr)
        d.snapshot_container()

class DockerNetworkScanTool(ThingToolsTool):
    label = "Docker: Network Scan"
    hotkey = "n"

    def run(self, context):
        d = DockerContainedDebugTools(context.ui.stdscr)
        d.network_scan()

class DockerHostNSTool(ThingToolsTool):
    label = "Docker: Try Host Namespace"
    hotkey = "h"

    def run(self, context):
        d = DockerContainedDebugTools(context.ui.stdscr)
        d.nsenter_host()

class DockerTools(ThingTools):
    name = "Docker"
    priority = 52  # near Kubernetes

    def detect(self, cwd, system_info):
        # Only show if we are *inside* a Docker container and `docker` is available
        try:
            cid = open("/proc/self/cgroup").read().strip().split("/")[-1]
            in_container = bool(cid)
        except:
            in_container = False

        docker_ok = shutil.which("docker") is not None
        return in_container and docker_ok

    def tools(self, context):
        return [
            DockerInspectTool(),
            DockerViewMountsTool(),
            DockerViewPortsTool(),
            DockerLogsTool(),
            DockerExecOtherTool(),
            DockerNetworkScanTool(),
            DockerHostNSTool(),
            DockerSnapshotTool(),
            DockerRestartTool(),
        ]


try:
    import boto3
except ImportError:
    boto3 = None

class ECSEnhancementsMixin:
    def __init__(self):
        # Detect task metadata endpoint
        self.ecs_metadata_uri = os.environ.get("ECS_CONTAINER_METADATA_URI_V4") \
                                or os.environ.get("ECS_CONTAINER_METADATA_URI")
        self._ecs_metadata_cache = None

    def _fetch_ecs_metadata(self):
        if not self.ecs_metadata_uri:
            return None
        if self._ecs_metadata_cache:
            return self._ecs_metadata_cache
        try:
            data = urllib.request.urlopen(self.ecs_metadata_uri, timeout=0.3).read().decode()
            self._ecs_metadata_cache = json.loads(data)
            return self._ecs_metadata_cache
        except:
            return None

    # ---------- Tier: ECS Task-Level Identity ----------
    def ecs_task_identity(self):
        meta = self._fetch_ecs_metadata()
        if not meta:
            return "[Not running inside ECS task]"
        return {
            "Cluster": meta.get("Cluster"),
            "TaskARN": meta.get("TaskARN"),
            "ContainerName": meta.get("Name"),
            "Image": meta.get("Image"),
            "LogDriver": meta.get("LogDriver"),
            "DockerId": meta.get("DockerId"),
        }

    # ---------- Task Peer Containers ----------
    def ecs_list_containers_in_task(self):
        meta = self._fetch_ecs_metadata()
        if not meta:
            return "[Not in ECS task]"
        return [c.get("Name") for c in meta.get("Containers", [])]

    # ---------- Task Role Credentials ----------
    def ecs_task_role_credentials(self):
        # This is different from EC2 Instance role credentials
        creds_uri = os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        if not creds_uri:
            return "[No ECS task credentials present]"
        url = "http://169.254.170.2" + creds_uri
        try:
            data = urllib.request.urlopen(url, timeout=0.3).read().decode()
            return json.loads(data)
        except Exception as e:
            return f"[Error] {e}"

    # ---------- Cluster Lookup (requires boto3 + perms) ----------
    def ecs_describe_task(self):
        if not self.can_use_boto:
            return "[No AWS API access]"
        meta = self._fetch_ecs_metadata()
        if not meta:
            return "[Not an ECS task]"
        ecs = boto3.client("ecs", region_name=self.region)
        try:
            return ecs.describe_tasks(
                cluster=meta["Cluster"],
                tasks=[meta["TaskARN"]]
            )
        except Exception as e:
            return f"[Error] {e}"

    def ecs_describe_cluster(self):
        if not self.can_use_boto:
            return "[No AWS API access]"
        meta = self._fetch_ecs_metadata()
        if not meta:
            return "[Not an ECS task]"
        ecs = boto3.client("ecs", region_name=self.region)
        try:
            return ecs.describe_clusters(clusters=[meta["Cluster"]])
        except Exception as e:
            return f"[Error] {e}"

import json


class SecretsAndServiceDiscoveryMixin:
    def __init__(self):
        # These only activate if boto3 + valid role
        if hasattr(self, "can_use_boto") and self.can_use_boto:
            self.ssm = boto3.client("ssm", region_name=self.region)
            self.secrets = boto3.client("secretsmanager", region_name=self.region)
            self.sd = boto3.client("servicediscovery", region_name=self.region)
        else:
            self.ssm = None
            self.secrets = None
            self.sd = None

    # ---------- SSM Parameter Store ----------

    def ssm_get(self, name, decrypt=True):
        if not self.ssm:
            return "[No AWS API access]"
        try:
            resp = self.ssm.get_parameter(Name=name, WithDecryption=decrypt)
            return resp["Parameter"]["Value"]
        except Exception as e:
            return f"[Error] {e}"

    def ssm_list(self, prefix="/"):
        if not self.ssm:
            return "[No AWS API access]"
        try:
            resp = self.ssm.describe_parameters(ParameterFilters=[
                {"Key": "Name", "Option": "BeginsWith", "Values": [prefix]}
            ])
            return [p["Name"] for p in resp.get("Parameters", [])]
        except Exception as e:
            return f"[Error] {e}"

    # ---------- Secrets Manager ----------

    def secret_get(self, name):
        if not self.secrets:
            return "[No AWS API access]"
        try:
            resp = self.secrets.get_secret_value(SecretId=name)
            if "SecretString" in resp:
                return resp["SecretString"]
            return f"[Binary secret: {len(resp.get('SecretBinary', b''))} bytes]"
        except Exception as e:
            return f"[Error] {e}"

    def secret_list(self):
        if not self.secrets:
            return "[No AWS API access]"
        try:
            resp = self.secrets.list_secrets()
            return [s["Name"] for s in resp.get("SecretList", [])]
        except Exception as e:
            return f"[Error] {e}"

    # ---------- Cloud Map Service Discovery ----------

    def cloudmap_list_services(self):
        if not self.sd:
            return "[No AWS API access]"
        try:
            resp = self.sd.list_services()
            return [(s["Id"], s["Name"]) for s in resp.get("Services", [])]
        except Exception as e:
            return f"[Error] {e}"

    def cloudmap_list_instances(self, service_id):
        if not self.sd:
            return "[No AWS API access]"
        try:
            resp = self.sd.list_instances(ServiceId=service_id)
            return resp.get("Instances", [])
        except Exception as e:
            return f"[Error] {e}"

    def cloudmap_resolve(self, service_name, namespace):
        if not self.sd:
            return "[No AWS API access]"
        fqdn = f"{service_name}.{namespace}"
        try:
            resp = self.sd.discover_instances(
                NamespaceName=namespace,
                ServiceName=service_name
            )
            return resp.get("Instances", [])
        except Exception as e:
            return f"[Error] resolving {fqdn}: {e}"
            
            
class EC2DebugTools(ECSEnhancementsMixin, SecretsAndServiceDiscoveryMixin):
    def __init__(self):
        self._imds_timeout = 0.2

        # Initialize mixins FIRST
        ECSEnhancementsMixin.__init__(self)
        SecretsAndServiceDiscoveryMixin.__init__(self)

        # Then continue original init work
        self.imds_base = "http://169.254.169.254/latest"
        self.token = self._fetch_imds_token()
        self.instance_id = self._imds("meta-data/instance-id")
        self.region = self._detect_region()
        self.role_name = self._imds("meta-data/iam/security-credentials/")
        self.creds = (
            self._imds(f"meta-data/iam/security-credentials/{self.role_name}")
            if self.role_name else None
        )

        self.can_use_boto = self._can_use_boto()

        if self.can_use_boto:
            self.ec2 = boto3.client("ec2", region_name=self.region)
        else:
            self.ec2 = None


    # ---------- IMDS helpers ----------

    def _fetch_imds_token(self):
        req = urllib.request.Request(
            self.imds_base + "/api/token",
            method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        )
        try:
            return urllib.request.urlopen(req, timeout=0.3).read().decode()
        except:
            return None

    def _imds(self, path):
        url = f"{self.imds_base}/{path}"
        headers = {"X-aws-ec2-metadata-token": self.token} if self.token else {}
        req = urllib.request.Request(url, headers=headers)
        try:
            return urllib.request.urlopen(req, timeout=0.3).read().decode()
        except:
            return None

    def _detect_region(self):
        doc = self._imds("dynamic/instance-identity/document")
        if not doc:
            return None
        try:
            return json.loads(doc).get("region")
        except:
            return None

    def _can_use_boto(self):
        if boto3 is None:
            return False
        if not self.creds:
            return False
        try:
            boto3.client("sts", region_name=self.region).get_caller_identity()
            return True
        except:
            return False

    # ---------- Tier 0: Always works ----------

    def basic_identity(self):
        out = {}
        out["hostname"] = subprocess.getoutput("hostname")
        out["os_release"] = subprocess.getoutput("cat /etc/os-release")
        return out

    def list_mounts(self):
        try:
            return open("/proc/mounts").read()
        except:
            return "[no mount info]"

    def network_info(self):
        return {
            "interfaces": subprocess.getoutput("ip a"),
            "routes": subprocess.getoutput("ip route"),
            "resolv.conf": subprocess.getoutput("cat /etc/resolv.conf"),
        }

    # ---------- Tier 1: IMDS metadata ----------

    def instance_metadata(self):
        if not self.instance_id:
            return "[IMDS not reachable]"
        return {
            "instance_id": self.instance_id,
            "region": self.region,
            "az": self._imds("meta-data/placement/availability-zone"),
            "ami_id": self._imds("meta-data/ami-id"),
            "instance_type": self._imds("meta-data/instance-type"),
            "local_ipv4": self._imds("meta-data/local-ipv4"),
            "public_ipv4": self._imds("meta-data/public-ipv4"),
            "security_groups": self._imds("meta-data/security-groups"),
        }

    # ---------- Tier 2: boto3-safe operations ----------

    def describe_self(self):
        if not self.can_use_boto:
            return "[No AWS API access]"
        try:
            resp = self.ec2.describe_instances(InstanceIds=[self.instance_id])
            return resp["Reservations"][0]["Instances"][0]
        except Exception as e:
            return f"[Error] {e}"

    def list_volumes(self):
        if not self.can_use_boto:
            return "[No AWS API access]"
        try:
            return self.ec2.describe_volumes(
                Filters=[{"Name": "attachment.instance-id", "Values": [self.instance_id]}]
            )["Volumes"]
        except Exception as e:
            return f"[Error] {e}"

    def snapshot_volume(self, volume_id, description="Debug Snapshot"):
        if not self.can_use_boto:
            return "[No AWS API access]"
        try:
            return self.ec2.create_snapshot(VolumeId=volume_id, Description=description)
        except Exception as e:
            return f"[Error] {e}"

    # ---------- Tier 3: Optional utilities ----------

    def ssm_shell(self):
        if shutil.which("aws") is None:
            return "[aws cli not installed]"
        subprocess.run(["aws", "ssm", "start-session", "--target", self.instance_id])
        return "[session closed]"


class EC2IdentityTool(ThingToolsTool):
    label = "EC2: Basic Identity"
    hotkey = "i"

    def run(self, context):
        ec2 = EC2DebugTools()
        info = ec2.basic_identity()
        text = f"Hostname:\n{info['hostname']}\n\nOS Release:\n{info['os_release']}"
        context.ui.popup_message(text)


class EC2InstanceMetadataTool(ThingToolsTool):
    label = "EC2: Instance Metadata"
    hotkey = "m"

    def run(self, context):
        ec2 = EC2DebugTools()
        meta = ec2.instance_metadata()
        if isinstance(meta, dict):
            text = json.dumps(meta, indent=2)
        else:
            text = str(meta)
        context.ui.popup_message(text)


class EC2DescribeSelfTool(ThingToolsTool):
    label = "EC2: Describe This Instance (boto3)"
    hotkey = "d"

    def run(self, context):
        ec2 = EC2DebugTools()
        info = ec2.describe_self()
        if isinstance(info, dict):
            text = json.dumps(info, indent=2)
        else:
            text = str(info)
        context.ui.popup_message(text)


class EC2ListVolumesTool(ThingToolsTool):
    label = "EC2: List Attached Volumes"
    hotkey = "v"

    def run(self, context):
        ec2 = EC2DebugTools()
        vols = ec2.list_volumes()
        if isinstance(vols, list):
            text = json.dumps(vols, indent=2)
        else:
            text = str(vols)
        context.ui.popup_message(text)


class EC2SnapshotVolumeTool(ThingToolsTool):
    label = "EC2: Snapshot a Volume"
    hotkey = "s"

    def run(self, context):
        ec2 = EC2DebugTools()
        vols = ec2.list_volumes()
        if not isinstance(vols, list) or not vols:
            context.ui.popup_message("No volumes available.")
            return

        # Show simple picker: choose first volume (easy default)
        vol_id = vols[0]["VolumeId"]
        resp = ec2.snapshot_volume(vol_id, description="Snapshot via file manager")
        context.ui.popup_message(str(resp))

class EC2SSMShellTool(ThingToolsTool):
    label = "EC2: SSM Shell to Self"
    hotkey = "x"

    def run(self, context):
        ec2 = EC2DebugTools()
        result = ec2.ssm_shell()
        context.ui.popup_message(str(result))


class EC2Tools(ThingTools):
    name = "EC2"
    priority = 65  # slightly below Kubernetes & Docker

    def detect(self, cwd, system_info):
        # Fast heuristics: does not block, does not call AWS
        # Works in EC2, ECS, EKS, Fargate, etc.T
        return (
            os.path.exists("/sys/hypervisor/uuid")
            or os.path.exists("/var/lib/cloud/instance")
            or os.environ.get("ECS_CONTAINER_METADATA_URI_V4")
            or os.environ.get("AWS_EXECUTION_ENV")
        )


    def tools(self, context):
        t = [
            EC2IdentityTool(),
            EC2InstanceMetadataTool(),
        ]

        ec2 = EC2DebugTools()
        if ec2.can_use_boto:
            t.extend([
                EC2DescribeSelfTool(),
                EC2ListVolumesTool(),
                EC2SnapshotVolumeTool(),
            ])
        if shutil.which("aws"):
            t.append(EC2SSMShellTool())

        return t


import os
import urllib.request
import json
import subprocess



# FILE MANAGER CORE

class ExtendedContextMenuModalOps:
    def __init__(self, stdscr, folder, ptype):
        self.stdscr = stdscr
        self.folder = folder
        self.ptype = ptype
        # fetch already-filtered ProjectAction objects
        self.actions = ProjectTypeFolderActions.for_type(ptype)
        self.sel = 0

    def run(self):
        curses.curs_set(0)
        while True:
            self.draw()
            ch = self.stdscr.getch()
            if ch in (ord('q'), 27):
                break
            elif ch == curses.KEY_UP:
                self.sel = max(0, self.sel - 1)
            elif ch == curses.KEY_DOWN:
                self.sel = min(len(self.actions) - 1, self.sel + 1)
            elif ch in (10, 13):  # enter
                action = self.actions[self.sel]
                # handle dynamic commands or static
                cmd = action.command() if callable(action.command) else action.command
                self.execute(cmd)

    def draw(self):
        self.stdscr.erase()
        self.stdscr.box()

        icon = PROJECT_TYPES[self.ptype].get("icon", "")
        title = f"{icon}  Actions for {os.path.basename(self.folder)}"
        self.stdscr.addstr(1, 2, title, curses.A_BOLD)

        for i, action in enumerate(self.actions):
            label = action.label
            attr = curses.A_REVERSE if i == self.sel else curses.A_NORMAL
            self.stdscr.addstr(3 + i, 4, label, attr)

        self.stdscr.refresh()

    def execute(self, cmd):
        curses.endwin()
        subprocess.run(cmd, cwd=self.folder, shell=True)
        input("\n[Press Enter to return]")
        curses.doupdate()


class ECSIdentityTool(ThingToolsTool):
    label = "ECS: Task Identity"
    hotkey = "i"

    def run(self, context):
        obj = EC2DebugTools()  # inherits the mixins in your codebase if combined
        info = obj.ecs_task_identity()
        if isinstance(info, dict):
            text = json.dumps(info, indent=2)
        else:
            text = str(info)
        context.ui.popup_message(text)


class ECSListContainersTool(ThingToolsTool):
    label = "ECS: Containers in Task"
    hotkey = "c"

    def run(self, context):
        obj = EC2DebugTools()
        result = obj.ecs_list_containers_in_task()
        if isinstance(result, list):
            text = "\n".join(result)
        else:
            text = str(result)
        context.ui.popup_message(text)


class ECSDescribeTaskTool(ThingToolsTool):
    label = "ECS: Describe Task (boto)"
    hotkey = "t"

    def run(self, context):
        obj = EC2DebugTools()
        result = obj.ecs_describe_task()
        if isinstance(result, dict):
            text = json.dumps(result, indent=2)
        else:
            text = str(result)
        context.ui.popup_message(text)


class ECSDescribeClusterTool(ThingToolsTool):
    label = "ECS: Describe Cluster (boto)"
    hotkey = "l"

    def run(self, context):
        obj = EC2DebugTools()
        result = obj.ecs_describe_cluster()
        if isinstance(result, dict):
            text = json.dumps(result, indent=2)
        else:
            text = str(result)
        context.ui.popup_message(text)


class SSMListParamsTool(ThingToolsTool):
    label = "SSM: List Parameters"
    hotkey = "p"

    def run(self, context):
        obj = EC2DebugTools()
        result = obj.ssm_list("/")
        if isinstance(result, list):
            text = "\n".join(result)
        else:
            text = str(result)
        context.ui.popup_message(text)


class SSMGetParamTool(ThingToolsTool):
    label = "SSM: Get Parameter"
    hotkey = "g"

    def run(self, context):
        name = context.ui.prompt("Parameter name:")
        if not name:
            return
        obj = EC2DebugTools()
        value = obj.ssm_get(name)
        context.ui.popup_message(str(value))


class SecretsListTool(ThingToolsTool):
    label = "Secrets: List"
    hotkey = "s"

    def run(self, context):
        obj = EC2DebugTools()
        result = obj.secret_list()
        if isinstance(result, list):
            text = "\n".join(result)
        else:
            text = str(result)
        context.ui.popup_message(text)


class SecretsGetTool(ThingToolsTool):
    label = "Secrets: Get"
    hotkey = "e"

    def run(self, context):
        name = context.ui.prompt("Secret name:")
        if not name:
            return
        obj = EC2DebugTools()
        result = obj.secret_get(name)
        context.ui.popup_message(str(result))


class CloudMapListServicesTool(ThingToolsTool):
    label = "CloudMap: List Services"
    hotkey = "m"

    def run(self, context):
        obj = EC2DebugTools()
        result = obj.cloudmap_list_services()
        if isinstance(result, list):
            text = "\n".join(f"{sid}  {name}" for sid, name in result)
        else:
            text = str(result)
        context.ui.popup_message(text)


from functools import lru_cache
import os

@lru_cache()
def _get_ec2():
    # Lazy initialization: heavy work happens only when needed
    return EC2DebugTools()


class ECSTools(ThingTools):
    name = "ECS"
    priority = 67

    def detect(self, cwd, system_info):
        # Fast, non-blocking ECS environment check
        return bool(
            os.environ.get("ECS_CONTAINER_METADATA_URI_V4")
            or os.environ.get("ECS_CONTAINER_METADATA_URI")
            or os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        )

    def tools(self, context):
        # Do NOT construct EC2DebugTools here — too slow
        ec2 = _get_ec2()

        t = [
            ECSIdentityTool(),
            ECSListContainersTool(),
        ]

        if ec2.can_use_boto:
            t.extend([
                ECSDescribeTaskTool(),
                ECSDescribeClusterTool(),
                SSMListParamsTool(),
                SSMGetParamTool(),
                SecretsListTool(),
                SecretsGetTool(),
                CloudMapListServicesTool(),
            ])

        return t



from dataclasses import dataclass
from typing import Callable, Optional, List, Dict

@dataclass
class ProjectAction:
    label: str
    command: str
    enabled: Optional[Callable[[], bool]] = None   # Optional condition check

    def is_enabled(self) -> bool:
        return self.enabled() if self.enabled else True


class ProjectTypeFolderActions:
    REGISTRY: Dict[str, List[ProjectAction]] = {
        "docker": [
            ProjectAction("Build Image",        lambda: f"docker build -t {docker_image_name()} ."),
            ProjectAction("Compose Up",         "docker compose up"),
            ProjectAction("Compose Down",       "docker compose down"),
            ProjectAction("Run Shell",          lambda: f"docker run -it --rm {docker_image_name()} sh"),
        ],

        "rn": [
            ProjectAction("Start Metro",        "npm start"),
            ProjectAction("Android Run",        "npx react-native run-android"),
            ProjectAction("iOS Run",            "npx react-native run-ios",
                          enabled=lambda: os.uname().sysname == "Darwin"),
            ProjectAction("Open Android Studio","studio ."),
        ],

        "flutter": [
            ProjectAction("flutter pub get",    "flutter pub get"),
            ProjectAction("Run App",            "flutter run"),
            ProjectAction("Build APK",          "flutter build apk"),
        ],

        "node": [
            ProjectAction("npm install",        "npm install"),
            ProjectAction("npm start",          "npm start"),
            ProjectAction("npm test",           "npm test"),
        ],

        "rust": [
            ProjectAction("cargo build",        "cargo build"),
            ProjectAction("cargo test",         "cargo test"),
            ProjectAction("cargo run",          "cargo run"),
        ],

        "go": [
            ProjectAction("go build",           "go build ./..."),
            ProjectAction("go test",            "go test ./..."),
        ],

        "python": [
            ProjectAction("Install deps",       "pip install -r requirements.txt",
                          enabled=lambda: os.path.exists("requirements.txt")),
            ProjectAction("Open venv shell",    "source .venv/bin/activate",
                          enabled=lambda: os.path.exists(".venv/bin/activate")),
        ],

        "git": [
            ProjectAction("Status",             "git status"),
            ProjectAction("Diff",               "git diff"),
            ProjectAction("Log",                "git log --oneline --graph --decorate"),
        ],
    }


    @classmethod
    def for_type(cls, ptype):
        return cls.REGISTRY.get(ptype, [])


import tempfile
import os
import shutil

SPECIAL_FOLDERS = {
    # exact names
    ".git":         {"icon": "", "label": "git repo"},
    "node_modules": {"icon": "📦", "label": "node deps"},
    "build":        {"icon": "🏗️", "label": "build output"},
    "__pycache__":  {"icon": "🐍", "label": "py cache"},
    ".venv":        {"icon": "🐢", "label": "python env"},

    # home-relative paths
    os.path.expanduser("~/Desktop"): {"icon": "🖥️", "label": "desktop"},
    os.path.expanduser("~/Documents"): {"icon": "📚", "label": "documents"},
    os.path.expanduser("~/Downloads"): {"icon": "⬇️", "label": "downloads"},
}

def is_git_repo(path):
    return os.path.isdir(os.path.join(path, ".git"))

def is_react_native_project(path):
    return (
        os.path.isfile(os.path.join(path, "package.json")) and
        (os.path.isdir(os.path.join(path, "android")) or
         os.path.isdir(os.path.join(path, "ios")))
    )
    
def is_docker_context(path):
    return (
        os.path.isfile(os.path.join(path, "Dockerfile")) or
        os.path.isfile(os.path.join(path, "docker-compose.yml")) or
        os.path.isfile(os.path.join(path, "docker-compose.yaml"))
    )

import os

def is_kubernetes_config(path):
    # First: try to list the directory safely
    try:
        entries = os.listdir(path)
    except (PermissionError, FileNotFoundError, NotADirectoryError):
        return False

    for f in entries:
        # We only care about YAML files; ignore anything else quickly
        if not (f.endswith(".yaml") or f.endswith(".yml")):
            continue

        full = os.path.join(path, f)

        # Try opening; ignore if unreadable or not a file
        try:
            with open(full, "r", errors="ignore") as test:
                first = test.read(200)
        except OSError:
            continue

        if "apiVersion:" in first and "kind:" in first:
            return True

    return False

    



def is_flutter_project(path):
    return (
        os.path.isfile(os.path.join(path, "pubspec.yaml")) and
        (os.path.isdir(os.path.join(path, "android")) or
         os.path.isdir(os.path.join(path, "ios")))
    )

def is_node_project(path):
    return os.path.isfile(os.path.join(path, "package.json"))

def is_rust_project(path):
    return os.path.isfile(os.path.join(path, "Cargo.toml"))

def is_go_project(path):
    return os.path.isfile(os.path.join(path, "go.mod"))

def is_python_env(path):
    return (
        os.path.isdir(os.path.join(path, ".venv")) or
        os.path.isfile(os.path.join(path, "requirements.txt"))
    )


def classify_project_hub(path):
    """Return True if this directory should be displayed in the pinned hub box."""
    if is_git_repo(path) and is_react_native_project(path):
        return True
    return False


filter_text = ""
filter_active = False

breadcrumb_mode = False
breadcrumb_index = 0
breadcrumb_positions = []

MAX_UNDO = 50
POUCH = []
UNDO_STACK = []
REDO_STACK = []

def get_breadcrumbs(path):
    parts = []
    p = path
    while True:
        p, tail = os.path.split(p)
        if tail:
            parts.append(tail)
        else:
            if p:
                parts.append(p)
            break
    return list(reversed(parts))

def classify_special(path, name):
    """
    Returns (icon) choosing ONE symbol based on priority.
    No labels here — labels are only used in header if desired.
    """
    full = os.path.join(path, name)

    # full-path classify first (like Desktop/Downloads if desired)
    if full in SPECIAL_FOLDERS:
        return SPECIAL_FOLDERS[full]["icon"]

    # priority order:
    if is_docker_context(full):
        return "🐳"
    if is_kubernetes_config(full):
        return "☸️"
    if is_react_native_project(full):
        return "⚛️📱"
    if is_flutter_project(full):
        return "🦋"
    if is_node_project(full):
        return "📦"
    if is_rust_project(full):
        return "🦀"
    if is_go_project(full):
        return "🐹"
    if is_python_env(full):
        return "🐍"
    if is_git_repo(full):
        return ""

    return None

def classify_project_type(path):
    if is_docker_context(path): return "docker"
    if is_kubernetes_config(path): return "k8s"
    if is_react_native_project(path): return "rn"
    if is_flutter_project(path): return "flutter"
    if is_node_project(path): return "node"
    if is_rust_project(path): return "rust"
    if is_go_project(path): return "go"
    if is_python_env(path): return "python"
    if is_git_repo(path): return "git"
    return None



import os, base64, tarfile, tempfile

TAR_SUFFIX = ".notals-tmp.tar"

KITTYPREFIX = "\x1b]1337;File="
KITTYSTOP = "\x07"  # BEL terminator

osc1337_buf = ""  # persistent buffer across iterations

def _process_osc1337_chunks(text, cwd, set_status):
    """
    Consume any OSC 1337 File frames inside 'text'.
    Returns (consumed_up_to_end, leftover), where 'leftover' is any tail
    that didn't contain a full BEL-terminated frame.
    """
    handled_any = False

    # Accumulate into the persistent buffer (closed over outside this func)
    global osc1337_buf
    osc1337_buf += text

    # We may have multiple frames; split on BEL but keep the tail
    parts = osc1337_buf.split(KITTYSTOP)
    osc1337_buf = parts[-1]  # keep tail with no BEL yet
    frames = parts[:-1]      # each ended with BEL

    for part in frames:
        # A part may contain multiple OSCs; we only care about the last File= start
        # Find all starts, handle each in order (usually just one)
        start = 0
        while True:
            idx = part.find(KITTYPREFIX, start)
            if idx == -1:
                break
            frame = part[idx + len(KITTYPREFIX):]  # content after "File="
            msg = drag_ops.receive_kitty_file(frame, cwd)
            if msg:
                set_status(msg)
            handled_any = True
            start = idx + len(KITTYPREFIX)

    return handled_any, osc1337_buf


def _flatten_name(name: str):
    """Remove any directory traversal attempts. Only keep safe basename."""
    name = name.rstrip("/").strip()
    base = os.path.basename(name)
    if base in ("", ".", ".."):
        return None
    return base


def _prompt_conflict(ui, path):
    """Ask how to resolve file overwrite conflicts."""
    choice = ui.list_menu_dialog(
        ["Overwrite", "Rename", "Cancel"],
        f"Exists: {os.path.basename(path)}"
    )
    return choice  # 0=overwrite, 1=rename, 2/cancel=None


class DragInOutOps:
    """
    Safe drag-in & drag-out for notals.
    Uses Kitty File Transfer protocol (OSC 1337).
    """

    def __init__(self,
                 pouch_ref,
                 ui_ref,
                 *,
                 default_drag_in_semantics="copy",
                 drag_out_format="uri",
                 allow_raw_payload=False,
                 payload_normalizer=None):

        self.POUCH = pouch_ref
        self.ui = ui_ref
        self.default_semantics = default_drag_in_semantics
        self.drag_out_format = drag_out_format
        self.allow_raw_payload = allow_raw_payload
        self.payload_normalizer = payload_normalizer

        # name -> {file: <fileobj>, size: int, dest: str}
        self._kitty_active_files = {}

    # ------------------------------------------------------------
    # Receive Kitty File
    # ------------------------------------------------------------

    def receive_kitty_file(self, encoded_frame, cwd):
        """
        Handles streamed Kitty OSC 1337 transfers securely.
        """

        if ":" not in encoded_frame:
            return "[Invalid frame]"

        header, b64data = encoded_frame.split(":", 1)

        # Parse metadata safely
        fields = {}
        for kv in header.split(";"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                fields[k.strip()] = v.strip()

        raw_name = fields.get("name", "")
        size = int(fields.get("size", "0"))
        offset = int(fields.get("offset", "0"))

        name = _flatten_name(raw_name)
        if not name:
            return "[Rejected: unsafe filename]"

        dest = os.path.join(cwd, name)
        data = base64.b64decode(b64data)

        # First chunk → handle overwrite / rename
        if offset == 0:
            if os.path.exists(dest):
                choice = _prompt_conflict(self.ui, dest)
                if choice in (None, 2):
                    return f"[Skip] {name}"
                elif choice == 1:
                    new_name = self.ui.prompt_input(f"Rename '{name}' → ")
                    if not new_name:
                        return f"[Skip] {name}"
                    name = _flatten_name(new_name)
                    dest = os.path.join(cwd, name)

            try:
                f = open(dest, "wb")
            except Exception as e:
                return f"[Write error: {e}]"

            # Track transfer session
            self._kitty_active_files[name] = {
                "file": f,
                "size": size,
                "dest": dest,
            }

        # Following chunks
        slot = self._kitty_active_files.get(name)
        if not slot:
            return f"[Error: unexpected chunk for {name}]"

        f = slot["file"]
        expected_size = slot["size"]

        f.seek(offset)
        f.write(data)

        # Complete transfer?
        if offset + len(data) >= expected_size:
            f.close()
            del self._kitty_active_files[name]

            # Directory mode: detect tar suffix and extract
            if name.endswith(TAR_SUFFIX):
                final_name = name[:-len(TAR_SUFFIX)]
                extract_dir = os.path.join(cwd, final_name)
                os.makedirs(extract_dir, exist_ok=True)
                try:
                    with tarfile.open(dest, "r") as tf:
                        tf.extractall(extract_dir)
                except Exception as e:
                    return f"[Extract error: {e}]"
                os.remove(dest)
                return f"[Received dir] {final_name}/"

            return f"[Received] {name}"


        return f"[Receiving… {name} {offset+len(data)}/{expected_size}]"

    # ------------------------------------------------------------
    # Request file from terminal (drag-in local → remote)
    # ------------------------------------------------------------
    def request_file_from_terminal(self, local_path):
        name = os.path.basename(local_path.rstrip("/"))

        if os.path.isdir(local_path):
            msg = (
                f"\x1b]1337;RequestFile="
                f"src={local_path};"
                f"name={name}{TAR_SUFFIX};"
                f"isdir=1"
                f"\x07"
            )
        else:
            msg = (
                f"\x1b]1337;RequestFile="
                f"src={local_path};"
                f"name={name};"
                f"\x07"
            )

        self.ui.send_raw(msg)
        return str(msg)


    # ------------------------------------------------------------
    # Drag IN
    # ------------------------------------------------------------
    def handle_drag_in(self, cwd, incoming, fallback_print, mode=None):
        
        
        if not isinstance(incoming, (list, tuple)):
            if not self.allow_raw_payload or not self.payload_normalizer:
                return ["[Rejected: raw drop payload]"]
            incoming = self.payload_normalizer(incoming)

        results = []
        for src in incoming:
            src = os.path.abspath(src)
            name = os.path.basename(src)
            resreqfile = self.request_file_from_terminal(src)
            results.append(resreqfile)
            results.append(f"[request file exited] {name}")
            

        self.ui.show_message("; ".join(results))
        return results
        
        
        # ------------------------------------------------------------
    # Drag OUT helpers (remote → local)
    # ------------------------------------------------------------
    def _send_file_to_terminal(self, path):
        """Send a single file to the terminal via OSC 1337."""
        name = os.path.basename(path)
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception as e:
            return f"[Send error: {e}]"

        b64 = base64.b64encode(data).decode()
        msg = f"\x1b]1337;File=name={name};size={len(data)}:{b64}\x07"
        self.ui.send_raw(msg)
        return f"[sent] {name}"

    def _send_directory_to_terminal(self, dir_path):
        """Tar a directory and send the tar."""
        base = os.path.basename(dir_path.rstrip("/"))
        with tempfile.NamedTemporaryFile(delete=False, suffix=".notals-out.tar") as tmp:
            tar_path = tmp.name

        try:
            with tarfile.open(tar_path, "w") as tf:
                tf.add(dir_path, arcname=base)
        except Exception as e:
            return f"[Dir tar error: {e}]"

        result = self._send_file_to_terminal(tar_path)
        os.remove(tar_path)
        return result

    # ------------------------------------------------------------
    # Drag OUT (public)
    # ------------------------------------------------------------
    def handle_drag_out(self, selected_paths):
        """
        Remote → local export.
        Terminal decides where to place drops.
        """
        results = []
        for p in selected_paths:
            if os.path.isdir(p):
                results.append(self._send_directory_to_terminal(p))
            else:
                results.append(self._send_file_to_terminal(p))

        self.ui.show_message("; ".join(results))
        return results


    # ------------------------------------------------------------
    # Drag OUT (remote → local)
    # ------------------------------------------------------------
    def export_paths(self, selected_paths):
        if not selected_paths:
            return ""
        if self.drag_out_format == "nul":
            return "\0".join(selected_paths)
        elif self.drag_out_format == "newline":
            return "\n".join(selected_paths)
        elif self.drag_out_format == "uri":
            return "\n".join(f"file://{p}" for p in selected_paths)
        raise ValueError(f"Unsupported drag_out_format: {self.drag_out_format}")


    # ------------------------------------------------------------
    # WezTerm Integration Helper
    # ------------------------------------------------------------
    @staticmethod
    def generate_wezterm_drag_integration(notals_command="notals"):
        return f"""\
-- ~/.wezterm.lua
local wezterm = require 'wezterm'
-- Conceptual: can't yet test on WezTerm on X11
wezterm.on("drag-drop", function(window, pane, files)
  local payload = "DROP_IN: " .. table.concat(files, " ") .. "\\n"
  window:perform_action(wezterm.action.SendString(payload), pane)
end)

return {{}}
"""

# Kitty drag to is correctly getting the file path on the local machine in the remote notals, but not yet getting the file
    @staticmethod
    def installation_instructions():
        return """\
Drag-In now performs immediate transfer via Kitty File Protocol.

Remote (notals) must:
  • detect OSC 1337 frames
  • call drag_ops.receive_kitty_file(frame, cwd)

Local (kitty) automatically sends file bytes when requested via:
  ESC ] 1337;RequestFile=name=FILENAME BEL


"""


# core UI
# ----------------- helpers -----------------
def join(p, name): return os.path.join(p, name)
def exists(p): return os.path.exists(p)
def is_dir(p): return os.path.isdir(p)

def print_session_log():
    try:
        with open(LOG_FILE) as f: lines = f.readlines()
    except FileNotFoundError:
        print("\n[No log entries this session]"); return
    print("\n========== notals Session Log ==========")
    for line in lines[-30:]:
        try:
            e = json.loads(line)
            print(f"{e['time']}  {e['action'].upper():5}  {e['name']}  {e['src']} → {e['dst']}")
        except Exception: print(line.strip())
    print("===========================================\n")

atexit.register(print_session_log)

def draw_filter_bar(win):
    if not filter_active:
        return
    rows, cols = win.getmaxyx()
    # Count matches from filtered view
    entries = list_entries(os.getcwd())
    count = len(entries)
    text = f"Filter: {filter_text}   ({count} match{'es' if count!=1 else ''})"
    # Bold reverse bar for clarity
    win.addstr(3, 2, text[:cols-4], curses.A_REVERSE)



def open_safe(path, ask_run=lambda cmd: False):
    """
    Safe 'open' handler for terminal/SSH environments.
    - Never modifies files.
    - Uses built-in inspection for text/binary/archives.
    - Optionally calls trusted CLI tools (chafa, pdftotext, less)
      if available and user confirms via ask_run(cmd).
    Returns a string summary or preview text.
    """
    if not os.path.exists(path):
        return "[Error: file not found]"
    if os.path.isdir(path):
        return "[DIR] — use Enter to navigate."

    # Try to detect MIME type
    mime, _ = mimetypes.guess_type(path)
    mime = mime or "application/octet-stream"

    # Use system 'file' command if available for more accurate detection
    if shutil.which("file"):
        try:
            result = subprocess.run(
                ["file", "--mime-type", "-b", path],
                capture_output=True, text=True, check=True
            )
            sys_mime = result.stdout.strip()
            if sys_mime:
                mime = sys_mime
        except Exception:
            pass

    size = os.path.getsize(path)

    # ---------- Text-like files ----------
    if mime.startswith("text/") or mime in (
        "application/json", "application/xml", "application/x-sh", "application/x-python",
        "application/x-perl", "application/x-yaml", "application/x-toml"
    ):
        if shutil.which("less") and ask_run(["less", "-R", path]):
            curses.endwin()
            try:
                subprocess.run(["less", "-R", path])
            finally:
                curses.doupdate()
            return "[Viewed with less]"
        try:
            with open(path, "r", errors="ignore") as f:
                lines = f.readlines()[:40]
            preview = "".join(lines)
            if len(lines) == 40:
                preview += "\n[...truncated...]"
            return preview or "[Empty file]"
        except Exception as e:
            return f"[Error reading text file: {e}]"

    # ---------- Images ----------
    if mime.startswith("image/"):
        if shutil.which("chafa"):
            cmd = ["chafa", "--fill=block", "--symbols=block", path]
            if ask_run(cmd):
                curses.endwin()
                try:
                    subprocess.run(cmd)
                finally:
                    curses.doupdate()
                return "[Displayed with chafa]"
        return f"[Image: {mime}, {size/1024:.1f} KB]"

    # ---------- PDFs ----------
    if mime == "application/pdf":
        if shutil.which("pdftotext"):
            cmd = ["pdftotext", "-layout", path, "-"]
            if ask_run(cmd):
                curses.endwin()
                try:
                    subprocess.run(cmd)
                finally:
                    curses.doupdate()
                return "[Text preview of PDF]"
        return f"[PDF document: {size/1024:.1f} KB]"

    # ---------- Archives ----------
    if mime in ("application/zip", "application/x-zip-compressed"):
        try:
            with zipfile.ZipFile(path) as z:
                names = z.namelist()[:15]
            return "ZIP archive:\n" + "\n".join(f"  {n}" for n in names) + (
                "\n[...truncated...]" if len(names) == 15 else ""
            )
        except Exception as e:
            return f"[Broken ZIP: {e}]"

    if mime in ("application/x-tar", "application/gzip", "application/x-gzip", "application/x-xz"):
        try:
            with tarfile.open(path) as t:
                names = t.getnames()[:15]
            return "TAR archive:\n" + "\n".join(f"  {n}" for n in names) + (
                "\n[...truncated...]" if len(names) == 15 else ""
            )
        except Exception as e:
            return f"[Broken TAR: {e}]"

    # ---------- Executables ----------
    if os.access(path, os.X_OK):
        cmd = [path]
        if ask_run(cmd):
            curses.endwin()
            try:
                subprocess.run(cmd)
                return "[Program executed]"
            finally:
                curses.doupdate()
        return "[Executable file — not run]"

    # ---------- Fallback: generic binary ----------
    try:
        with open(path, "rb") as f:
            data = f.read(64)
        snippet = " ".join(f"{b:02x}" for b in data[:32])
        return f"[Binary file: {mime}, {size/1024:.1f} KB]\nFirst bytes: {snippet}..."
    except Exception as e:
        return f"[Unreadable binary file: {e}]"


def log_action(action, src, dst, name):
    e = {
        "time": datetime.datetime.now().isoformat(timespec="seconds"),
        "action": action, "src": src, "dst": dst, "name": name
    }
    UNDO_STACK.append(e)
    if len(UNDO_STACK) > MAX_UNDO: UNDO_STACK.pop(0)
    with open(LOG_FILE, "a") as f: f.write(json.dumps(e) + "\n")
    
    
def text_preview_dialog(stdscr, title, text):
    """Display multi-line text safely inside curses."""
    rows, cols = stdscr.getmaxyx()
    width = min(100, cols - 4)
    height = min(rows - 4, 30)
    win = curses.newwin(height, width, (rows - height)//2, (cols - width)//2)
    win.keypad(True)
    text_lines = text.splitlines()
    offset = 0
    while True:
        win.erase(); win.box()
        win.addstr(1, 2, title[:width-4], curses.A_BOLD)
        for i, line in enumerate(text_lines[offset:offset + height - 5]):
            try:
                win.addstr(3+i, 2, line[:width-4])
            except curses.error:
                pass
        win.addstr(height-2, 2, "[↑/↓ scroll  q/Esc close]", curses.A_DIM)
        win.refresh()
        ch = win.getch()
        if ch in (ord('q'), 27, 10, 13):
            break
        elif ch == curses.KEY_DOWN and offset < len(text_lines) - (height - 5):
            offset += 1
        elif ch == curses.KEY_UP and offset > 0:
            offset -= 1


# ---------------- dialogs -----------------
def path_input_dialog(stdscr, prompt="Path:"):
    curses.curs_set(1)
    rows, cols = stdscr.getmaxyx()
    width = min(80, cols - 4)
    win = curses.newwin(3, width, rows//2, (cols - width)//2)
    user = ""
    pos = 0

    def redraw():
        win.erase()
        win.box()
        # Display prompt + user buffer
        shown = prompt + " " + user
        win.addstr(1, 2, shown[:width-4])
        # Set cursor position
        win.move(1, 2 + len(prompt) + 1 + pos)
        win.refresh()

    redraw()

    while True:
        ch = win.getch()

        # ESC
        if ch == 27:
            curses.curs_set(0)
            return None

        # ENTER
        if ch in (10, 13):
            curses.curs_set(0)
            return user.strip() or None

        # BACKSPACE
        if ch in (curses.KEY_BACKSPACE, 127, 8):
            if pos > 0:
                user = user[:pos-1] + user[pos:]
                pos -= 1
            redraw()
            continue

        # LEFT
        if ch == curses.KEY_LEFT:
            pos = max(0, pos - 1)
            redraw()
            continue

        # RIGHT
        if ch == curses.KEY_RIGHT:
            pos = min(len(user), pos + 1)
            redraw()
            continue

        # TAB: directory autocompletion
        if ch == 9:  # Tab
            text = user.strip()
            if text:
                expanded = os.path.expanduser(text)
                dirname, partial = os.path.split(expanded)
                if dirname == "":
                    dirname = "."
                if os.path.isdir(dirname):
                    try:
                        candidates = [
                            d for d in os.listdir(dirname)
                            if d.startswith(partial) and os.path.isdir(os.path.join(dirname, d))
                        ]
                        if len(candidates) == 1:
                            # one unique dir
                            new = os.path.join(dirname, candidates[0]) + os.sep
                            # convert back to user-visible form if ~ was used
                            if text.startswith("~"):
                                home = os.path.expanduser("~")
                                if new.startswith(home):
                                    new = "~" + new[len(home):]
                            user = new
                            pos = len(user)
                        elif len(candidates) > 1:
                            prefix = os.path.commonprefix(candidates)
                            if prefix and prefix != partial:
                                new = os.path.join(dirname, prefix)
                                if os.path.isdir(new):
                                    new = new + os.sep
                                # convert back to ~ if applicable
                                if text.startswith("~"):
                                    home = os.path.expanduser("~")
                                    if new.startswith(home):
                                        new = "~" + new[len(home):]
                                user = new
                                pos = len(user)
                    except Exception:
                        pass
            redraw()
            continue

        # Printable chars
        if 32 <= ch <= 126:
            user = user[:pos] + chr(ch) + user[pos:]
            pos += 1
            redraw()
            continue

        # If we reach here, just redraw to avoid cursor drift
        redraw()


def confirm_ack(stdscr, title, body_lines, required_phrase):
    rows,cols = stdscr.getmaxyx()
    width = min(80, max(len(required_phrase)+20, max((len(l) for l in body_lines), default=0)+6))
    height = 6+len(body_lines)
    win = curses.newwin(height,width,(rows-height)//2,(cols-width)//2)
    curses.curs_set(1)
    user=""
    while True:
        win.erase(); win.box(); win.addstr(1,2,title,curses.A_BOLD)
        for i,l in enumerate(body_lines): win.addstr(2+i,2,l[:width-4])
        win.addstr(2+len(body_lines),2,f"Type exactly: {required_phrase}",curses.A_DIM)
        win.addstr(3+len(body_lines),2,user)
        win.refresh()
        ch=win.getch()
        if ch==27: curses.curs_set(0); return False
        if ch in (10,13):
            curses.curs_set(0)
            return user==required_phrase
        if ch in (curses.KEY_BACKSPACE,127,8): user=user[:-1]
        elif 32<=ch<=126: user+=chr(ch)

def inspect_file_dialog(stdscr,path):
    rows,cols = stdscr.getmaxyx()
    width,minh = min(100,cols-4),min(20,rows-4)
    win = curses.newwin(minh,width,(rows-minh)//2,(cols-width)//2)
    win.box()
    win.addstr(1,2,f"Inspect: {os.path.basename(path)}",curses.A_BOLD)

    try:
        st = os.stat(path)
        mime,_ = mimetypes.guess_type(path)

        lines = [
            f"Path: {path}",
            f"Inode: {st.st_ino}",
            f"Permissions: {oct(st.st_mode & 0o777)}",
            f"Owner: {pwd.getpwuid(st.st_uid).pw_name}:{grp.getgrgid(st.st_gid).gr_name}",
            f"Modified: {datetime.datetime.fromtimestamp(st.st_mtime)}"
        ]

        if os.path.isdir(path):
            lines.append("Type: directory")

            # Item count
            try:
                items = os.listdir(path)
                lines.append(f"Contains: {len(items)} items")
            except Exception as e:
                items = []
                lines.append(f"[Error listing directory: {e}]")

            # Disk usage: use du if available for accuracy
            size_str = None
            if shutil.which("du"):
                try:
                    result = subprocess.run(
                        ["du", "-sh", path],
                        capture_output=True, text=True, check=True
                    )
                    size_str = result.stdout.split()[0]
                except Exception:
                    pass

            # Fallback: safe Python walk with bound
            if size_str is None:
                max_items = 5000   # safety cap
                total = 0
                scanned = 0
                try:
                    for root, dirs, files in os.walk(path):
                        for fname in files:
                            if scanned > max_items:
                                raise RuntimeError("too many files")
                            fpath = os.path.join(root, fname)
                            try:
                                total += os.path.getsize(fpath)
                            except:
                                pass
                            scanned += 1
                    size_str = f"{total/1024/1024:.1f} MB (approx)"
                except:
                    size_str = "[too large to estimate safely]"

            lines.append(f"Disk Usage: {size_str}")

            # Show first few entries
            for name in items[:10]:
                lines.append(f" • {name}")
            if len(items) > 10:
                lines.append(" • ...")

        else:
            # File inspection remains the same
            size = st.st_size
            lines.append(f"Type: {mime or 'unknown'}")
            lines.append(f"Size: {size} bytes")
            try:
                with open(path,"rb") as f:
                    data = f.read(65536)
                lines.append(f"SHA256(first 64k): {hashlib.sha256(data).hexdigest()[:16]}…")
            except:
                lines.append("[Unreadable binary]")

    except Exception as e:
        lines=[f"[Error: {e}]"]

    for i,l in enumerate(lines[:minh-4]):
        try:
            win.addstr(3+i,2,l[:width-4])
        except:
            pass

    win.addstr(minh-2,2,"[q/Esc]",curses.A_DIM)
    win.refresh()
    while True:
        if win.getch() in (27,ord('q'),10,13):
            break


# ---------------- pouch -----------------
def add_to_pouch(path,name,action="copy"): POUCH.append({"path":join(path,name),"action":action})
def clear_pouch(): POUCH.clear()
def toggle_pouch_item(i):
    if 0<=i<len(POUCH):
        POUCH[i]["action"]="move" if POUCH[i]["action"]=="copy" else "copy"

def pouch_manager(stdscr):
    sel = 0
    while True:
        stdscr.erase()
        stdscr.addstr(1, 2, f"Pouch — {len(POUCH)} item(s)", curses.A_BOLD)
        stdscr.addstr(2, 2, "Items here will be moved or copied when executed.", curses.A_DIM)

        # List pouch contents
        for i, item in enumerate(POUCH):
            a = curses.A_REVERSE if i == sel else curses.A_NORMAL
            stdscr.addstr(4 + i, 4, f"[{item['action']}] {item['path']}", a)

        # Explain current selection
        if POUCH:
            current = POUCH[sel]
            explanation = (
                "copy: duplicates into destination"
                if current["action"] == "copy"
                else "move: relocates into destination"
            )
            stdscr.addstr(curses.LINES - 5, 2, explanation, curses.A_DIM)

        # Controls
        stdscr.addstr(
            curses.LINES - 2, 2,
            "[Enter=execute  t=toggle copy/move  d=remove item  c=clear pouch  q=back]",
            curses.A_DIM
        )
        stdscr.refresh()

        ch = stdscr.getch()

        # Navigation
        if ch in (ord('q'), 27):
            break
        if ch == curses.KEY_DOWN:
            sel = min(sel + 1, len(POUCH) - 1)
        if ch == curses.KEY_UP:
            sel = max(sel - 1, 0)

        # Toggle copy/move
        if ch == ord('t') and POUCH:
            toggle_pouch_item(sel)

        # Remove selected item
        if ch == ord('d') and POUCH:
            del POUCH[sel]
            sel = max(0, sel - 1)
            continue

        # Clear entire pouch
        if ch == ord('c'):
            clear_pouch()
            sel = 0
            continue

        # Execute pouch actions
        if ch in (10, 13) and POUCH:
            target = path_input_dialog(stdscr, "Destination:")
            if not target:
                continue

            # Confirmation preview
            rows, cols = stdscr.getmaxyx()
            confirm_win = curses.newwin(10, min(80, cols - 4), (rows - 10)//2, 2)
            confirm_win.box()
            confirm_win.addstr(1, 2, "Execute pouch operations:", curses.A_BOLD)
            confirm_win.addstr(3, 2, f"Destination: {target}")
            for i, item in enumerate(POUCH[:5]):
                confirm_win.addstr(5 + i, 4, f"[{item['action']}] {item['path']}")
            if len(POUCH) > 5:
                confirm_win.addstr(10 - 3, 4, f"...and {len(POUCH)-5} more")
            confirm_win.addstr(10 - 2, 2, "Press Enter to confirm, q to cancel.", curses.A_DIM)
            confirm_win.refresh()

            c2 = confirm_win.getch()
            if c2 in (ord('q'), 27):
                continue

            # Execute with simple progress
            for index, item in enumerate(POUCH):
                srcp, name = os.path.split(item["path"])
                progress = f"{index+1}/{len(POUCH)}: {name}"
                stdscr.addstr(curses.LINES - 3, 2, progress.ljust(cols-4))
                stdscr.refresh()
                safer_move_or_copy(stdscr, srcp, name, target, item["action"])

            clear_pouch()
            sel = 0
            break



# ---------------- fs operations -----------------
def list_entries(path):
    try:
        items = sorted(os.listdir(path))
    except Exception:
        return []

    # Apply filter if active
    if filter_active and filter_text:
        scored = []
        for n in items:
            s = fuzzy_score(n, filter_text)
            if s is not None:
                scored.append((s, n))
        # Sort by score (descending), then name
        scored.sort(key=lambda t: (-t[0], t[1]))
        items = [n for _, n in scored]


    dirs = [(n, "dir") for n in items if is_dir(join(path, n))]
    files = [(n, "file") for n in items if not is_dir(join(path, n))]
    return dirs + files

# currently unused    
def atomic_copy_or_move(src_full, dst_full, action):
    dst_dir = os.path.dirname(dst_full)

    # temp file/dir in same directory, so rename is atomic
    with tempfile.TemporaryDirectory(dir=dst_dir) as tmp_dir:
        tmp_target = os.path.join(tmp_dir, os.path.basename(dst_full))

        if action == "move":
            # Move into temp dir first (same filesystem)
            shutil.move(src_full, tmp_target)
        else:
            if os.path.isdir(src_full):
                shutil.copytree(src_full, tmp_target)
            else:
                shutil.copy2(src_full, tmp_target)

        # Now atomically rename to final destination
        os.replace(tmp_target, dst_full)


def safer_move_or_copy(stdscr, srcp, name, dst, action):
    """
    Safely move or copy an entry `name` from directory `srcp` into directory `dst`.
    Blocks dangerous/illogical operations:
      - moving/copying an item into itself
      - moving/copying a directory into its own subtree
      - overwriting the same path (no-op)
    Uses realpath to avoid symlink tricks.
    """
    src_full = join(srcp, name)
    dst_full = join(dst, name)

    # Existence check
    if not exists(src_full):
        return False

    # Resolve symlinks and normalize
    try:
        rp_src_full = os.path.realpath(src_full)
        rp_dst_full = os.path.realpath(dst_full)
    except Exception:
        return False

    # Helper: is rp_b inside rp_a (strictly within subtree)
    def is_strict_subpath(rp_a, rp_b):
        rp_a = os.path.join(rp_a, '')  # ensure trailing sep
        rp_b = os.path.join(rp_b, '')
        return rp_b.startswith(rp_a) and rp_b != rp_a

    # 1) Block exact same path (no-op / self-overwrite)
    try:
        # samefile handles cases where both exist; fall back to realpath compare otherwise
        if exists(src_full) and exists(dst_full) and os.path.samefile(src_full, dst_full):
            # Nothing sensible to do; refuse
            return False
    except Exception:
        # If samefile fails, compare realpaths
        if rp_src_full == rp_dst_full:
            return False

    # 2) Block directory -> its own subtree (e.g., /a/dir -> /a/dir/dir or deeper)
    if is_dir(src_full):
        # Destination is inside source subtree?
        if is_strict_subpath(rp_src_full, rp_dst_full):
            # Dangerous recursive move/copy; refuse
            return False

    # 3) If destination exists, confirm before removing
    if exists(dst_full):
        # Build a human-readable summary for the confirmation window
        desc = []
        if is_dir(dst_full):
            try:
                count = len(os.listdir(dst_full))
                desc.append(f"Directory contains {count} item(s).")
            except Exception:
                desc.append("Directory content count unavailable.")
        else:
            desc.append(f"File size: {os.path.getsize(dst_full)} bytes.")
        desc.append(f"Destination path: {dst_full}")

        phrase = f"overwrite: {name}"
        if not confirm_ack(
            stdscr,
            f"Confirm overwrite of {name}",
            desc,
            phrase
        ):
            # User declined or escaped; cancel
            return False

        # --- right before deletion ---
        new_rp_dst_full = os.path.realpath(dst_full)
        if new_rp_dst_full != rp_dst_full:
            # Path changed after confirmation: abort
            return False

        try:
            if is_dir(dst_full):
                shutil.rmtree(dst_full)
            else:
                os.remove(dst_full)
        except Exception:
            return False

    # 4) Perform the operation
    try:
        new_rp_src_full = os.path.realpath(src_full)
        new_rp_dst_full = os.path.realpath(dst_full)
        if new_rp_src_full != rp_src_full or new_rp_dst_full != rp_dst_full:
            return False
        if is_dir(new_rp_src_full) and is_strict_subpath(new_rp_src_full, new_rp_dst_full):
            return False

        dst_dir = os.path.dirname(dst_full)
        tmp_suffix = ".tmp_copy"
        tmp_full = dst_full + tmp_suffix

        # Clean up any old tmp file first
        if os.path.exists(tmp_full):
            shutil.rmtree(tmp_full, ignore_errors=True)

        # Stage into temp name
        if action == "move":
            shutil.move(src_full, tmp_full)
        else:
            if is_dir(src_full):
                shutil.copytree(src_full, tmp_full)
            else:
                shutil.copy2(src_full, tmp_full)

        # Atomic replace
        os.replace(tmp_full, dst_full)

        log_action(action, srcp, dst, name)
        return True

    except Exception as e:
        print(f"[Error] atomic safer_move_or_copy: {e}")
        # Clean up tmp_full if exists
        if 'tmp_full' in locals() and os.path.exists(tmp_full):
            shutil.rmtree(tmp_full, ignore_errors=True)
        return False

    
def undo_last():
    """Undo the most recent move or copy using the log stack."""
    if not UNDO_STACK:
        return "[Undo] Nothing to undo."
    entry = UNDO_STACK.pop()
    a, src, dst, name = entry["action"], entry["src"], entry["dst"], entry["name"]
    src_full = os.path.join(src, name)
    dst_full = os.path.join(dst, name)

    if a == "move":
        if os.path.exists(dst_full):
            try:
                shutil.move(dst_full, src)
                REDO_STACK.append(entry)  # store for redo
                return f"[Undo] Moved {name} back to {src}"
            except Exception as e:
                return f"[Undo failed] {e}"
        else:
            return f"[Undo] {name} not found in {dst}"
    elif a == "copy":
        if os.path.exists(dst_full):
            try:
                if os.path.isdir(dst_full):
                    shutil.rmtree(dst_full)
                else:
                    os.remove(dst_full)
                REDO_STACK.append(entry)
                return f"[Undo] Removed copied {name} from {dst}"
            except Exception as e:
                return f"[Undo failed] {e}"
        else:
            return f"[Undo] Nothing to remove"
    return "[Undo] Unsupported action."

def redo_last():
    """Redo the most recently undone action."""
    if not REDO_STACK:
        return "[Redo] Nothing to redo."
    entry = REDO_STACK.pop()
    a, src, dst, name = entry["action"], entry["src"], entry["dst"], entry["name"]
    src_full = os.path.join(src, name)
    dst_full = os.path.join(dst, name)

    try:
        if a == "move":
            shutil.move(src_full, dst)
        elif a == "copy":
            if os.path.isdir(src_full):
                shutil.copytree(src_full, dst_full)
            else:
                shutil.copy2(src_full, dst_full)
        UNDO_STACK.append(entry)
        return f"[Redo] {a} {name} to {dst}"
    except Exception as e:
        return f"[Redo failed] {e}"


# ---------------- drawing -----------------
ASCII_FOLDER=["  ________  "," / ____  \\__","/_/___/__/ /|","|        | / "]
FOLDER_H=len(ASCII_FOLDER)+1; LINE_X=4; TOP_Y=6; HELP_FOOT=2; STATUS_FOOT=1

def sadd(win,y,x,s,a=0):
    try: win.addstr(int(y),int(x),s,a)
    except curses.error: pass


def wait_for_keypress_before_return():
    """Pause before re-entering curses after running an external program."""
    try:
        input("\n[Press Enter to return to notals...]")
    except (EOFError, KeyboardInterrupt):
        pass


def run_shell_command_dialog(stdscr, file_path):
    """Prompt for a shell command and safely run it with '{}' substitution."""
    cmd_template = path_input_dialog(stdscr, "Command to run (use {} for file):")
    if not cmd_template:
        return

    # Safely substitute the selected path
    quoted_path = shlex.quote(file_path)
    cmd = cmd_template.replace("{}", quoted_path)

    # Build confirmation message, split into wrapped lines for curses
    display_cmd = f"Will execute: {cmd}"
    body_lines = [display_cmd, "Proceed carefully."]

    confirm = confirm_ack(
        stdscr,
        "Run command?",
        body_lines,
        "run"
    )
    if not confirm:
        return

    curses.endwin()
    try:
        subprocess.run(cmd, shell=True)
        wait_for_keypress_before_return()
    finally:
        curses.doupdate()

    return f"[Executed] {cmd}"

def context_menu_dialog(stdscr, path, name):
    full = join(path, name)
    ptype = classify_project_type(full) if is_dir(full) else None

    menu_items = ["Inspect"]
    if ptype:
        menu_items.append("Project Actions")

    rows, cols = stdscr.getmaxyx()
    width = max(len(m) for m in menu_items) + 6
    height = len(menu_items) + 4

    win = curses.newwin(height, width, (rows - height)//2, (cols - width)//2)
    win.keypad(True)
    sel = 0

    while True:
        win.erase(); win.box()
        win.addstr(1, 2, name, curses.A_BOLD)

        for i, m in enumerate(menu_items):
            a = curses.A_REVERSE if i == sel else curses.A_NORMAL
            win.addstr(3+i, 2, m, a)

        win.refresh()
        ch = win.getch()

        if ch in (27, ord('q')):
            return
        elif ch == curses.KEY_UP:
            sel = max(sel-1, 0)
        elif ch == curses.KEY_DOWN:
            sel = min(sel+1, len(menu_items)-1)
        elif ch in (10, 13):
            choice = menu_items[sel]
            if choice == "Inspect":
                inspect_file_dialog(stdscr, full)
            elif choice == "Project Actions" and ptype:
                ExtendedContextMenuModalOps(stdscr, full, ptype).run()
            return
            
        elif ch == curses.KEY_MOUSE:
            _, mx, my, _, b = curses.getmouse()

            wy, wx = win.getbegyx()
            wh, ww = win.getmaxyx()

            # Pointer inside menu bounds?
            if wy <= my < wy + wh and wx <= mx < wx + ww:
                row = my - wy
                index = row - 3  # menu items start at row 3 in the menu window

                # Hover highlight (no click required)
                if 0 <= index < len(menu_items):
                    if sel != index:
                        sel = index
                        # Redraw menu with new highlight
                        win.erase()
                        win.box()
                        win.addstr(1, 2, name, curses.A_BOLD)
                        for i, m in enumerate(menu_items):
                            style = curses.A_REVERSE if i == sel else curses.A_NORMAL
                            win.addstr(3+i, 2, m, style)
                        win.refresh()

                # **Only trigger activation on release**
                if b & curses.BUTTON1_RELEASED:
                    choice = menu_items[sel]
                    if choice == "Inspect":
                        inspect_file_dialog(stdscr, full)   # returns back into curses normally
                        return
                    elif choice == "Project Actions" and ptype:
                        ExtendedContextMenuModalOps(stdscr, full, ptype).run()
                        return


def draw_back_bar(win,drop=False):
    a=curses.A_BOLD if drop else curses.A_NORMAL
    sadd(win,0,2,"╔"+"═"*64+"╗",a)
    sadd(win,1,2,"║  ← [Drag back]                                                 ║",a)
    sadd(win,2,2,"╚"+"═"*64+"╝",a)

def build_layout(entries):
    layout=[]; top=0
    for i,(n,t) in enumerate(entries):
        h=FOLDER_H if t=="dir" else 1
        layout.append({"idx":i,"name":n,"type":t,"height":h,"top":top,"bottom":top+h-1})
        top+=h
    return layout,top

def ensure_visible(offset,vis_h,item_top,item_bottom):
    if item_top<offset: return item_top
    if item_bottom>=offset+vis_h: return max(0,item_bottom-vis_h+1)
    return offset

def draw_view(win, path, sel_idx, offset, drag=None, drop_hover_idx=None, drop_back=False):
    win.erase()
    draw_back_bar(win, drop_back)

    # ----- HEADER SPECIAL TAGS -----
    tags = []

    if is_docker_context(path):
        tags.append("🐳")
    elif is_kubernetes_config(path):
        tags.append("☸️")

    if is_react_native_project(path):
        tags.append("⚛️📱")
    elif is_flutter_project(path):
        tags.append("🦋")

    if is_node_project(path):
        tags.append("📦")
    if is_rust_project(path):
        tags.append("🦀")
    if is_go_project(path):
        tags.append("🐹")
    if is_python_env(path):
        tags.append("🐍")

    if is_git_repo(path):
        tags.append("")

    if tags:
        try:
            win.addstr(1, 35, " ".join(tags), curses.A_BOLD)
        except curses.error:
            pass


    # ----- Breadcrumbs -----
    breadcrumbs = get_breadcrumbs(path)
    x = 2
    global breadcrumb_positions
    breadcrumb_positions = []
    for i, part in enumerate(breadcrumbs):
        style = curses.A_BOLD
        if breadcrumb_mode and i == breadcrumb_index:
            style |= curses.A_REVERSE
        start = x
        end = x + len(part)
        breadcrumb_positions.append((start, end, i))
        sadd(win, 4, x, part, style)
        x = end + 3

    draw_filter_bar(win)

    # ----- Build List -----
    entries = list_entries(path)
    layout, total_h = build_layout(entries)
    vis_h = max(0, curses.LINES - TOP_Y - (HELP_FOOT + STATUS_FOOT))
    if total_h <= vis_h:
        offset = 0
    else:
        offset = max(0, min(offset, total_h - vis_h))

    # ----- Draw Items -----
    for cell in layout:
        if cell["bottom"] < offset or cell["top"] >= offset + vis_h:
            continue

        y0 = TOP_Y + (cell["top"] - offset)

        if cell["type"] == "dir":
            fullpath = os.path.join(path, cell["name"])

            # highlight if selected
            a = curses.A_REVERSE if cell["idx"] == sel_idx else curses.A_NORMAL

            # literally bar it
            if is_barging(fullpath):
                a |= curses.A_UNDERLINE

            # drag hover highlight stays on top
            if drop_hover_idx == cell["idx"]:
                a |= curses.A_BOLD
            # Folder icon detection
            icon = classify_special(path, cell["name"])
            icon = icon or "📁"

            # Folder graphic block
            for i, line in enumerate(ASCII_FOLDER):
                draw_y = y0 + i
                if TOP_Y <= draw_y < TOP_Y + vis_h:
                    sadd(win, draw_y, LINE_X, line, a)

            sadd(win, y0 + len(ASCII_FOLDER), LINE_X + 1, f"{icon} {cell['name']}", a)

        else:
            a = curses.A_REVERSE if cell["idx"] == sel_idx else curses.A_NORMAL
            if drag and drag[0] == "file" and drag[1] == cell["name"]:
                a |= curses.A_DIM
            if TOP_Y <= y0 < TOP_Y + vis_h:
                sadd(win, y0, LINE_X, f"📄 {cell['name']}", a)

    sadd(win, curses.LINES - 2, 2,
         "[↑↓PgUpPgDnHomeEnd MouseWheel Enter/Open b/Back DragDrop q/Quit]",
         curses.A_DIM)

    win.refresh()
    return layout, total_h, vis_h, offset


def find_cell_at(layout,line):
    for c in layout:
        if c["top"]<=line<=c["bottom"]: return c
    return None
    
def fuzzy_score(name, pattern):
    """
    Simple, predictable fuzzy matching:
    Score = number of pattern chars found in order, weighted by compactness.
    Higher = better. Returns None if pattern does not match.
    """
    name_low = name.lower()
    pat_low = pattern.lower()

    i = 0
    positions = []
    for ch in pat_low:
        pos = name_low.find(ch, i)
        if pos < 0:
            return None
        positions.append(pos)
        i = pos + 1

    # Compactness penalty: closer matches score higher
    span = positions[-1] - positions[0] + 1
    return len(pat_low) * 100 - span   # bigger score = better


def get_thingtools_context(ui, cwd, selected_file, selected_files, system_info, clipboard):
    return ThingToolsToolContext(
        ui=ui,
        cwd=cwd,
        selected_file=selected_file,
        selected_files=selected_files,
        system_info=system_info,
        clipboard=clipboard,
    )


def generic_menu_dialog(stdscr, title, items):
    curses.curs_set(0)
    sel = 0

    while True:
        stdscr.erase()
        rows, cols = stdscr.getmaxyx()
        stdscr.box()
        stdscr.addstr(1, 2, title, curses.A_BOLD)

        for i, item in enumerate(items):
            style = curses.A_REVERSE if i == sel else curses.A_NORMAL
            stdscr.addstr(3 + i, 4, item[:cols-8], style)

        stdscr.refresh()

        ch = stdscr.getch()
        if ch in (ord("q"), 27):       # ESC or q exits
            return None
        elif ch == curses.KEY_UP:
            sel = max(0, sel - 1)
        elif ch == curses.KEY_DOWN:
            sel = min(len(items) - 1, sel + 1)
        elif ch in (10, 13):           # Enter
            return sel



# this is a stub atm and should use the safer code used by the file manager core
class NotalsUI:
    def __init__(self, stdscr):
        self.stdscr = stdscr

    def show_message(self, msg):
        rows, cols = self.stdscr.getmaxyx()
        self.stdscr.addstr(rows-3, 2, msg[:cols-4])
        self.stdscr.refresh()

    def confirm_dialog(self, question):
        return confirm_ack(self.stdscr, "Confirm", [question], "yes")

    def input_dialog(self, prompt):
        return path_input_dialog(self.stdscr, prompt)

    def text_preview_dialog(self, text, title):
        return text_preview_dialog(self.stdscr, title, text)
        


    def list_menu_dialog(self, items, title):
        print("[DEBUG] Items:", items)

        # If items are (hotkey, label) tuples → Tools menu → generic menu
        if items and isinstance(items[0], (tuple, list)):
            return generic_menu_dialog(self.stdscr, title, [
                (f"{hk}  {label}" if hk else label)
                for (hk, label) in items
            ])

        # If items are strings but **not paths**, also generic
        if items and isinstance(items[0], str) and "/" not in items[0]:
            return generic_menu_dialog(self.stdscr, title, items)

        # Otherwise, assume it's a filesystem list
        return context_menu_dialog(self.stdscr, title, items)



    def open_file_editor(self, path):
        curses.endwin()
        try:
            curses.wrapper(lambda s: DumbEd(s, path).run())
        finally:
            curses.doupdate()

    def fs_move(self, src, dst):
        safer_move_or_copy(self.stdscr, os.path.dirname(src), os.path.basename(src), dst, "move")

    def fs_copy(self, src, dst):
        safer_move_or_copy(self.stdscr, os.path.dirname(src), os.path.basename(src), dst, "copy")

    def fs_trash(self, path):
        shutil.move(path, os.path.expanduser("~/.local/share/notals-experimental-stub/files/"))

    def redraw(self):
        curses.doupdate()

def prompt_input(stdscr, prompt):
    curses.curs_set(1)
    rows, cols = stdscr.getmaxyx()
    stdscr.addstr(rows-3, 2, " "*(cols-4))
    stdscr.addstr(rows-3, 2, prompt, curses.A_BOLD)
    stdscr.refresh()
    buf = ""
    while True:
        ch = stdscr.getch()
        if ch in (10, 13):  # Enter
            curses.curs_set(0)
            return buf.strip()
        elif ch in (27,):  # ESC
            curses.curs_set(0)
            return None
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            buf = buf[:-1]
        elif 32 <= ch <= 126:
            buf += chr(ch)
        stdscr.addstr(rows-3, 2, " "*(cols-4))
        stdscr.addstr(rows-3, 2, prompt + buf)
        stdscr.refresh()

def safe_basename_only(name):
    # Disallow traversal or subpaths
    return name and "/" not in name and "\\" not in name and ".." not in name

def safe_rename(path, old, new, set_status):
    old_full = os.path.join(path, old)
    new_full = os.path.join(path, new)

    if not safe_basename_only(new):
        set_status("[Invalid name]")
        return
    if os.path.exists(new_full):
        set_status("[Already exists]")
        return
    try:
        os.rename(old_full, new_full)
        # Log as move: src = path, dst = path, name = old
        # Undo will move it back, which is correct for rename.
        log_action("move", path, path, old)
        set_status(f"[Renamed] {old} → {new}")
    except Exception as e:
        set_status(f"[Rename failed] {e}")


def safe_name_for_make(name):
    """
    Allow:
      file:  "foo"
      dir:   "foo/"

    Disallow:
      "foo/bar"
      "../x"
      "x.."
      "x/y/"
      "foo//"
    """
    if not name:
        return False

    # Allow one trailing "/" only
    if name.endswith("/"):
        core = name[:-1]
    else:
        core = name

    # Must still be non-empty after removing slash
    if not core:
        return False

    # The core still must be a plain basename
    if "/" in core or "\\" in core or ".." in core:
        return False

    return True


def safe_make(path, name, set_status):
    if not safe_name_for_make(name):
        set_status("[Invalid name]")
        return

    full = os.path.join(path, name.rstrip("/"))
    is_dir_flag = name.endswith("/")

    if os.path.exists(full):
        set_status("[Already exists]")
        return

    try:
        if is_dir_flag:
            os.mkdir(full)
            log_action("copy", path, path, name.rstrip("/"))
            set_status(f"[Dir created] {name.rstrip('/')}/")
        else:
            with open(full, "w") as f:
                pass
            log_action("copy", path, path, name)
            set_status(f"[File created] {name}")
    except Exception as e:
        set_status(f"[Create failed] {e}")



# ---------------- main -----------------
def main(stdscr):
    global filter_active, filter_text, breadcrumb_mode, breadcrumb_positions, breadcrumb_index
    
    # Construct a minimal UI object that can send raw escape sequences
    class NotalsUIProxy:
        def __init__(self, scr):
            self.stdscr = scr
            self.show_status_function = lambda x:print(x)
        def send_raw(self, s: str):
            import sys
            self.show_status_function("raw"+ s)
            #breakpoint()
            sys.stdout.write(s)
            sys.stdout.flush()

        def show_message(self, msg):
            self.show_status_function(msg)
            pass
            

    
    tool_groups = all_thingtools_classes()

    #for m in all_modules:
    #    if m.detect(): show menu section for it
    # Let Ctrl-S / Ctrl-Q reach the program (not terminal flow-control)
    import subprocess
    subprocess.call(["stty", "-ixon"])

    curses.curs_set(0); stdscr.keypad(True)
        # Mouse: enable press/drag/release + motion reports (xterm 1002/1006)
    curses.mouseinterval(0)
    try:
        avail, _old = curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
        if not avail:
            curses.mousemask(curses.ALL_MOUSE_EVENTS)
    except Exception:
        curses.mousemask(curses.ALL_MOUSE_EVENTS)

    try: stdscr.mousemask(curses.ALL_MOUSE_EVENTS|curses.REPORT_MOUSE_POSITION)
    except AttributeError: pass
    path=os.getcwd(); history=[]; sel_idx=0; offset=0; drag=None; status=""
    B4=getattr(curses,"BUTTON4_PRESSED",0); B5=getattr(curses,"BUTTON5_PRESSED",0)

    def set_status(msg):
        nonlocal status
        status=msg; sadd(stdscr,curses.LINES-3,2," "*(curses.COLS-4)); sadd(stdscr,curses.LINES-3,2,msg)
        
        
    ui1337 = NotalsUIProxy(stdscr)
    
    drag_ops = DragInOutOps(
        pouch_ref=POUCH,   # or your existing pouch list
        ui_ref=ui1337,
        default_drag_in_semantics="copy",   # immediate transfer
        drag_out_format="uri",
        allow_raw_payload=False,
        payload_normalizer=None
    )
    ui1337.show_status_function = set_status

    layout,total_h,vis_h,offset=draw_view(stdscr,path,sel_idx,offset)
    
    last_click_time = 0
    double_click_grace = 1.5  # seconds; adjust if needed

    while True:

        # Read one key; keep blocking behavior
        ch = stdscr.getch()

        # ---------- Paste/drag detection (non-invasive) ----------
        def _read_more_nowait(max_bytes=8192):
            # Temporarily nonblocking to drain a paste burst quickly
            stdscr.nodelay(True)
            buf = []
            try:
                while True:
                    c = stdscr.getch()
                    if c == -1:
                        break
                    buf.append(c)
                    if len(buf) >= max_bytes:
                        break
            finally:
                stdscr.nodelay(False)
            return buf

        def _ints_to_text(seq):
            # Convert ints -> bytes -> str losslessly for ASCII-ish paste
            try:
                return bytes([(c if isinstance(c,int) else c) & 0xFF for c in seq]).decode(errors="ignore")
            except Exception:
                return ""

        def _push_back(seq):
            # Return chars to input so normal flow isn’t broken
            for c in reversed(seq):
                curses.ungetch(c)

        # 1) Bracketed paste: ESC [ 200 ~ ... ESC [ 201 ~
        # 1) ESC-prefixed sequences (OSC / bracketed paste / others)
        if ch == 27:  # ESC
            tail = _read_more_nowait()
            text = _ints_to_text([27] + tail)
            set_status(f"[attempt consume osc 1337]")
            # First: try to consume any OSC 1337 File frames in this burst
            handled, _ = _process_osc1337_chunks(text, path, set_status)
            if handled:
                # We consumed OSC frames; nothing to push back for them.
                # But there might be non-OSC content in 'text' that your UI
                # expects to see. If you need to preserve that, you can parse
                # more carefully. Most cases won't need it.
                set_status(f"[consumed osc 1337] {os.path.basename(p)}")
                continue

            # Next: your existing bracketed paste handling
            if text.startswith("\x1b[200~"):
                set_status(f"[attempt consume brack paste]")
                end_idx = text.find("\x1b[201~")
                if end_idx != -1:
                    set_status(f"[consuming brack paste]")
                    payload = text[6:end_idx]  # strip "\x1b[200~"
                    first_line = payload.splitlines()[0].strip()
                    if first_line.startswith("file://") or first_line.startswith("/"):
                        p = first_line[7:] if first_line.startswith("file://") else first_line
                        drag_ops.handle_drag_in(path, [p])
                        set_status(f"[consumed brack paste]")
                        set_status(f"[consumed brack] {os.path.basename(p)}")
                        continue
            # Not OSC-1337 and not bracketed paste → push back so normal keys work
            _push_back(tail)


        # 2) Fallback: quick-burst paste without bracketed markers
        #    Heuristic: a slash or 'f' (for file://) followed by a burst, no newlines
        if ch in (ord('/'), ord('f')):
            tail = _read_more_nowait()
            candidate = _ints_to_text([ch] + tail).strip()
            if ("\x1b" not in candidate) and ("\n" not in candidate):
                if candidate.startswith("file://") or candidate.startswith("/"):
                    p = candidate[7:] if candidate.startswith("file://") else candidate
                    # If multiple paths were pasted, take the first token/line
                    p = p.split()[0].splitlines()[0]
                    set_status(f"[request2] {os.path.basename(p)}")
                    drag_ops.handle_drag_in(path, [p], set_status)
                    
                    continue
            # Not a path → push back so the UI sees what user typed
            _push_back(tail)
        # ---------- end paste/drag detection ----------



        entries=list_entries(path)
        layout,total_h=build_layout(entries)
        vis_h=max(0,curses.LINES-TOP_Y-(HELP_FOOT+STATUS_FOOT))
        if total_h<=vis_h: offset=0
        else: offset=max(0,min(offset,total_h-vis_h))
        sel_idx=max(0,min(sel_idx,len(entries)-1)) if entries else 0

        if ch in (ord("q"),27): break
        
        elif filter_active:
            # Exit filter mode
            if ch in (27, curses.KEY_EXIT):  # ESC
                filter_active = False
                filter_text = ""
                set_status("[Filter cleared]")
            elif ch in (10, 13):  # Enter
                # keep filter active but do not change it
                pass
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                filter_text = filter_text[:-1]
            elif 32 <= ch <= 126:
                filter_text += chr(ch)
            # After any edit, reset selection and scroll
            sel_idx = 0
            offset = 0
            
        elif breadcrumb_mode:
            if ch in (27, ord('q')):  # ESC exits breadcrumb mode
                breadcrumb_mode = False
                set_status("[Breadcrumb exit]")
            elif ch == curses.KEY_LEFT:
                breadcrumb_index = max(0, breadcrumb_index - 1)
            elif ch == curses.KEY_RIGHT:
                breadcrumb_index = min(len(get_breadcrumbs(path)) - 1, breadcrumb_index + 1)
            elif ch in (10, 13):  # Enter = jump
                new_parts = get_breadcrumbs(path)[:breadcrumb_index + 1]
                new_path = "/" + "/".join(p for p in new_parts if p != "/")
                if os.path.isdir(new_path):
                    history.append((path, sel_idx, offset))
                    path = new_path
                    chdir(path, set_status)
                    breadcrumb_mode = False
                    sel_idx = 0
                    offset = 0
                    set_status(f"[Jump] {path}")


        elif ch == ord("b") and history:
            path, sel_idx, offset = history.pop()
            chdir(path, set_status)
        
        elif ch == ord("i") and entries:
            e = entries[sel_idx]
            full_path = join(path, e[0])
            inspect_file_dialog(stdscr, full_path)
            
        elif ch == ord('D') and entries:
            e = entries[sel_idx]
            name = e[0]
            full_path = os.path.join(path, name)

            phrase = "trash"
            ok = confirm_ack(
                stdscr,
                title="Move to Trash",
                body_lines=[
                    f"Are you sure you want to move:",
                    f"  {name}",
                    "",
                    "This action is reversible (Undo works)."
                ],
                required_phrase=phrase
            )

            if ok:
                move_to_trash(stdscr, path, name, set_status)
            else:
                set_status("[Canceled]")


        elif ch == ord('R') and entries:
            e = entries[sel_idx]
            old = e[0]
            new = prompt_input(stdscr, f"Rename {old} → ")
            if new:
                safe_rename(path, old, new, set_status)

  
        elif ch == ord('M'):
            name = prompt_input(stdscr, "New name (end with / for directory): ")
            if name:
                safe_make(path, name, set_status)


        elif ch == ord("!"):
            if entries:
                e = entries[sel_idx]
                full_path = join(path, e[0])
                
                msg = run_shell_command_dialog(stdscr, full_path)
                # Refresh after command: external tools may have changed the FS or cwd
                new_path = os.getcwd()
                path = new_path
                sel_idx = 0
                offset = 0
                if msg:
                    set_status(msg)


        elif ch == ord('f'):  # enter or exit filter mode
            filter_active = True
            filter_text = ""
            set_status("[Filter mode] Type to filter. ESC to cancel.")

        elif ch == 10 and entries:
            e = entries[sel_idx]
            newp = join(path, e[0])
            if e[1] == "dir":
                history.append((path, sel_idx, offset))
                path = newp
                chdir(path, set_status)
                sel_idx = 0
                offset = 0
            else:
                # Use open_safe() to preview files safely
                def ask_run(cmd):
                    # small inline confirmation
                    msg = f"Run external tool: {' '.join(cmd)} ? [y/N]"
                    rows, cols = stdscr.getmaxyx()
                    stdscr.addstr(rows-3, 2, " " * (cols-4))
                    stdscr.addstr(rows-3, 2, msg, curses.A_BOLD)
                    stdscr.refresh()
                    ch2 = stdscr.getch()
                    return ch2 in (ord('y'), ord('Y'))

                preview = open_safe(newp, ask_run=ask_run)
                text_preview_dialog(stdscr, f"Preview: {e[0]}", preview)
        elif ch == ord('a'):
            ptype = classify_project_type(path)
            if ptype:
                ExtendedContextMenuModalOps(stdscr, path, ptype).run()
                # After modal: screen may be stale, so redraw from clean state:
                sel_idx = 0
                offset = 0
                set_status(f"[Project actions: {ptype}]")
            else:
                set_status("[No project actions available here]")

        elif ch==curses.KEY_DOWN and entries:
            sel_idx=min(sel_idx+1,len(entries)-1); c=layout[sel_idx]; offset=ensure_visible(offset,vis_h,c["top"],c["bottom"])
        elif ch==curses.KEY_UP and entries:
            sel_idx=max(sel_idx-1,0); c=layout[sel_idx]; offset=ensure_visible(offset,vis_h,c["top"],c["bottom"])
        elif ch==curses.KEY_NPAGE and entries:
            offset=min(offset+vis_h,max(0,total_h-vis_h)); cell=find_cell_at(layout,offset) or layout[-1]; sel_idx=cell["idx"]
        elif ch==curses.KEY_PPAGE and entries:
            offset=max(0,offset-vis_h); cell=find_cell_at(layout,offset) or layout[0]; sel_idx=cell["idx"]
        elif ch==ord("p") and entries:
            e=entries[sel_idx]; add_to_pouch(path,e[0]); set_status(f"[Pouch] added {e[0]}")
        elif ch == ord("Z"):  # Shift+Z
            curses.endwin()
            print("\n=== TOOL INITIALIZATION TIMING ===\n")
            for name, d in TOOL_PROF.items():
                print(f"{name}: detect={d['detect']*1000:7.2f} ms, tools={d['tools']*1000:7.2f} ms")
            input("\nPress Enter to return...")
            curses.doupdate()

        elif ch == ord('h'):
            breadcrumb_mode = True
            breadcrumb_index = len(get_breadcrumbs(path)) - 1
            set_status("[Breadcrumb mode] Use ← → Enter, Esc to exit.")
            
       
        elif ch == ord("T") and entries:
            # Determine the selected item
            name, typ = entries[sel_idx]
            selected_path = os.path.join(path, name)

            # Build UI context
            ui = NotalsUI(stdscr)

            ctx = get_thingtools_context(
                ui=ui,
                cwd=path,
                selected_file=selected_path,
                selected_files=[selected_path],  # we do not support multi-select yet
                system_info=None,
                clipboard=None,
            )

            # Gather relevant tools
            tools = ThingTools.gather_tools(ctx, all_thingtools_classes())
            if not tools:
                set_status("[No tools available here]")
                continue

            # Build menu choices (display strings only)
            items = [
                (f"[{hk}] {label}" if hk else label)
                for (hk, label, tool) in tools
            ]

            # Present selection menu → returns index or None
            choice = ctx.list_menu(items, title="Tools")
            if choice is None:

                set_status("[Cancelled]")
                continue

            # Unpack the actual tool object using the same index
            hk, label, tool = tools[choice]

            try:
                tool.safe_run(ctx)
                set_status(f"[Ran tool: {label}]")
            except Exception as e:
                set_status(f"[Tool error: {e}]")






        elif ch == ord('U'):
            msg = undo_last()
            set_status(msg)
        elif ch == ord('u'):  # go up one directory
            parent = os.path.dirname(path)
            if parent and parent != path and os.path.isdir(parent):
                history.append((path, sel_idx, offset))
                path = parent
                chdir(path, set_status)
                sel_idx = 0
                offset = 0
                set_status(f"[Up] {path}/")
            else:
                set_status("[No parent directory]")

        elif ch==ord("P"): pouch_manager(stdscr)
        elif ch == ord("g"):
            target = path_input_dialog(stdscr, "Jump to:")
            if target:
                target = os.path.abspath(os.path.expanduser(target))
                if exists(target):
                    history.append((path, sel_idx, offset))
                    path = target
                    chdir(path, set_status)
                    sel_idx = 0
                    offset = 0
                else:
                    set_status(f"[Not found] {target}")

        elif ch == curses.KEY_MOUSE:
            try:
                id_, mx, my, _, bs = curses.getmouse()
                
                # breadcrumb teleport
                if my == 4:
                    for start, end, idx in breadcrumb_positions:
                        if start <= mx <= end:
                            # Jump there
                            new_parts = get_breadcrumbs(path)[:idx+1]

                            new_path = "/" + "/".join(p for p in new_parts if p != "/")
                            if exists(new_path):
                                history.append((path, sel_idx, offset))
                                path = new_path
                                chdir(path, set_status)
                                sel_idx, offset = 0, 0
                                status = f"[Jump] {path}"
                            break


                # --- normalize buttons across terminals ---
                B1_PRESS = getattr(curses, "BUTTON1_PRESSED", 0)
                B1_REL   = getattr(curses, "BUTTON1_RELEASED", 0)
                B1_CLICK = getattr(curses, "BUTTON1_CLICKED", 0)
                B1_DBL   = getattr(curses, "BUTTON1_DOUBLE_CLICKED", 0)
                B1_TRP   = getattr(curses, "BUTTON1_TRIPLE_CLICKED", 0)
                B1_MOVE  = getattr(curses, "BUTTON1_MOVED", 0)
                B4       = getattr(curses, "BUTTON4_PRESSED", 0)  # wheel up
                B5       = getattr(curses, "BUTTON5_PRESSED", 0)  # wheel down

                # back bar hover
                drop_back = (0 <= my <= 2)

                # wheel scroll
                if bs & B4:
                    offset = max(0, offset - max(1, vis_h // 4))
                if bs & B5:
                    offset = min(max(0, total_h - vis_h), offset + max(1, vis_h // 4))

                # map screen y -> logical line for hover
                if TOP_Y <= my < TOP_Y + vis_h:
                    logical_line = offset + (my - TOP_Y)
                else:
                    logical_line = None

                hover_cell = find_cell_at(layout, logical_line) if logical_line is not None else None
                hover_idx  = hover_cell["idx"] if hover_cell else None
                
                # Right-click -> context menu
                RIGHT_PRESS  = getattr(curses, "BUTTON3_PRESSED", 0)
                RIGHT_REL    = getattr(curses, "BUTTON3_RELEASED", 0)
                RIGHT_CLICK  = RIGHT_PRESS | RIGHT_REL

                #set_status(f"[RCLICKATT] /")
                if (bs & RIGHT_CLICK) and hover_idx is not None:
                    e = entries[hover_idx]
                    context_menu_dialog(stdscr, path, e[0])
                    continue




                # Double-click: open folders immediately
                if (bs & B1_DBL) and hover_idx is not None:
                    e = entries[hover_idx]
                    if e[1] == "dir":
                        history.append((path, sel_idx, offset))
                        path, sel_idx, offset = join(path, e[0]), 0, 0
                        set_status(f"[OPEN] {e[0]}/")
                        drag = None
                        continue  # redraw immediately

                elif (bs & (B1_PRESS | B1_CLICK)) and hover_idx is not None:
                    now = time.time()
                    if now - last_click_time < double_click_grace:
                        # Still inside cooldown → treat as possible double-click, skip drag
                        drag = None
                        last_click_time = now
                        set_status(f"[WAIT] {'📁' if e[1]=='dir' else '📄'} {e[0]}")
                        e = entries[hover_idx]
                        if e[1] == "dir":
                            history.append((path, sel_idx, offset))
                            path, sel_idx, offset = join(path, e[0]), 0, 0
                            set_status(f"[OPEN] {e[0]}/")
                            drag = None
                            continue  # redraw immediately
                    else:
                        e = entries[hover_idx]
                        drag = (e[1], e[0], path)
                        set_status(f"[DRAG] {'📁' if e[1]=='dir' else '📄'} {e[0]}")
                        sel_idx = hover_idx
                        last_click_time = now



                # update hover highlight while moving (if movement bit exists or repeated PRESS events)
                if drag and (bs & (B1_MOVE | B1_PRESS | B1_CLICK)):
                    pass  # just having hover_idx recomputed above is enough for highlight

                # release -> drop
                if (bs & B1_REL) and drag:
                    dtype, name, srcp = drag
                    dropped = False

                    # drop to parent bar
                    parent = os.path.dirname(path)
                    if drop_back and parent and parent != path and exists(parent):
                        if safer_move_or_copy(stdscr, srcp, name, parent, "move"):
                            set_status(f"[MOVE] {name} → {parent}")
                        else:
                            set_status(f"[MOVE FAILED] {name}")
                        dropped = True

                    # drop onto a hovered directory
                    elif hover_cell is not None and entries[hover_cell["idx"]][1] == "dir":
                        dest = join(path, entries[hover_cell["idx"]][0])
                        if safer_move_or_copy(stdscr, srcp, name, dest, "move"):
                            set_status(f"[MOVE] {name} → {dest}")
                        else:
                            set_status(f"[MOVE FAILED] {name}")
                        dropped = True

                    if not dropped:
                        set_status("[DROP] No valid target")
                    drag = None  # end drag

                # click without drag -> just select
                if (bs & B1_CLICK) and hover_idx is not None and not drag:
                    sel_idx = hover_idx

                # keep selection in view
                if entries:
                    cell = layout[sel_idx]
                    offset = ensure_visible(offset, vis_h, cell["top"], cell["bottom"])

            except curses.error:
                pass

        layout,total_h,vis_h,offset=draw_view(stdscr,path,sel_idx,offset,
            drag=drag,
            drop_hover_idx=(hover_idx if 'hover_idx' in locals() and hover_idx is not None and entries[hover_idx][1]=='dir' else None),
            drop_back=('drop_back' in locals() and drop_back))
        if status: set_status(status)
        
    # Optional: print final cwd so shell wrappers can cd into it
    if os.environ.get("NOTALS_PRINT_CWD") == "1":
        curses.endwin()
        print(path, end="")

if __name__=="__main__":
    curses.wrapper(main)

