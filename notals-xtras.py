# notals (not-a-ls) extras
# future use / conceptual / do not use

# think about tool context containing:
#run_capture(cmd, cwd=...)
#text_preview_dialog(text, title=...)
#current_selection() returning an object with .name
#selected_file_path (property)
#open_file(path, line=...)
#which(name) 
#program_path
#path_input(prompt) 
#capture(cmd)
#tempfile(prefix) 
#run_interactive(cmd, cwd=...) 

class PortDiscoveryTools(ThingTools):
    name = "Ports / Network"
    priority = 45

    def detect(self, cwd, system_info):
        # Only show if at least one of the tools exists
        return (
            shutil.which("ss") or
            shutil.which("netstat") or
            shutil.which("lsof")
        ) is not None

    def tools(self, context):
        return [
            PortListTool(),
            PortProcessesTool(),
            ListeningOnlyTool(),
        ]

class PortListTool(ThingToolsTool):
    label = "Show All Network Sockets"
    hotkey = "a"
    description = "List TCP/UDP ports and endpoints."

    def run(self, context):
        cmd = None
        if shutil.which("ss"):
            cmd = "ss -tunap"
        elif shutil.which("lsof"):
            cmd = "lsof -i -P -n"
        elif shutil.which("netstat"):
            cmd = "netstat -tunap"
        else:
            context.notify("No port inspection tools installed.")
            return

        out = context.run_capture(cmd)
        context.text_preview_dialog(out, title="All Network Sockets")

class ListeningOnlyTool(ThingToolsTool):
    label = "Show Listening Ports"
    hotkey = "l"
    description = "Only ports in LISTEN state."

    def run(self, context):
        cmd = None
        if shutil.which("ss"):
            cmd = "ss -ltnup"
        elif shutil.which("lsof"):
            cmd = "lsof -i -P -n | grep LISTEN"
        elif shutil.which("netstat"):
            cmd = "netstat -ltnup"
        else:
            context.notify("No listening-port tools available.")
            return

        out = context.run_capture(cmd)
        context.text_preview_dialog(out, title="Listening Ports")

class PortProcessesTool(ThingToolsTool):
    label = "Process Port Map"
    hotkey = "p"
    description = "Select a running process and view its network use."

    def run(self, context):
        # get process list
        ps_out = context.run_capture("ps -eo pid,comm --sort=comm")
        lines = [l.strip() for l in ps_out.splitlines()[1:] if l.strip()]
        choices = []
        for ln in lines:
            parts = ln.split(None, 1)
            if len(parts) == 2:
                pid, cmd = parts
                choices.append(f"{pid}  {cmd}")

        choice = context.list_menu(choices, title="Choose Process:")
        if not choice:
            return

        pid = choice.split()[0]

        if shutil.which("lsof"):
            cmd = f"lsof -a -p {pid} -i -P -n"
        elif shutil.which("ss"):
            cmd = f"ss -p | grep 'pid={pid},'"
        else:
            context.notify("Process socket inspection requires lsof or ss.")
            return

        out = context.run_capture(cmd)
        context.text_preview_dialog(out, title=f"Ports for PID {pid}")

class HttpServeTools(ThingTools):
    name = "HTTP Server"
    priority = 50

    def detect(self, cwd, system_info):
        # Always available since we're running Python.
        return True

    def tools(self, context):
        return [
            HttpServeHereTool(),
        ]


class HttpServeHereTool(ThingToolsTool):
    label = "Serve This Folder Over HTTP"
    hotkey = "h"
    description = "Start a local web server in this directory."

    def run(self, context):
        # Prompt for port, default to 8000
        port = context.input_prompt("Port to serve on (default 8000): ")
        if not port.strip():
            port = "8000"

        # Validate port input
        try:
            port_int = int(port)
            if port_int < 1 or port_int > 65535:
                raise ValueError()
        except:
            context.notify("Invalid port number.")
            return

        # Use the working directory the user is currently viewing
        cwd = context.cwd

        context.notify(f"Serving {cwd} on http://0.0.0.0:{port_int} (Ctrl+C to stop)")

        # Run interactively so curses is suspended properly
        context.run_interactive(
            f"python3 -m http.server {port_int} --bind 0.0.0.0",
            cwd=cwd
        )

        context.notify("HTTP server stopped.")

class SearchTools(ThingTools):
    name = "Search"
    priority = 40

    def detect(self, cwd, system_info):
        # Always allow search — fallback to grep if rg missing
        return True

    def tools(self, context):
        return [
            FilenameSearchTool(),
            ContentSearchTool(),
        ]


class FilenameSearchTool(ThingToolsTool):
    label = "Search Filenames"
    hotkey = "f"
    description = "Search for files whose names match the query."

    def run(self, context):
        query = context.input_prompt("Search filenames for:")
        if not query:
            return

        # Prefer rg, fallback to find
        if shutil.which("rg"):
            cmd = f"rg --files | rg -i {shlex.quote(query)}"
        else:
            cmd = f"find . -iname '*{query}*'"

        output = context.run_capture(cmd, cwd=context.cwd)
        if not output.strip():
            context.notify("No matching filenames found.")
            return

        # Show results list, allow open
        lines = output.strip().splitlines()
        choice = context.list_menu(lines, title="Matches (Enter = open):")
        if choice:
            target = os.path.join(context.cwd, choice)
            context.open_file(target)


class ContentSearchTool(ThingToolsTool):
    label = "Search Inside Files (rg / grep)"
    hotkey = "s"
    description = "Search file contents for a text pattern (Unicode supported)."

    def run(self, context):
        pattern = context.input_prompt("Search text pattern:")
        if not pattern:
            return

        # Prefer ripgrep for UTF-8/Unicode correctness
        if shutil.which("rg"):
            cmd = f"rg -n --hidden --color never {shlex.quote(pattern)}"
        else:
            # grep -R supports unicode but may choke on binaries, so avoid them
            cmd = f"grep -RIn --binary-files=without-match {shlex.quote(pattern)} ."

        output = context.run_capture(cmd, cwd=context.cwd)

        if not output.strip():
            context.notify("No text matches found.")
            return

        # Show results and allow navigation / open-at-line
        lines = output.strip().splitlines()
        choice = context.list_menu(lines, title="Matches (Enter = open at line):")
        if not choice:
            return

        # Parse "file:line:rest" format
        parts = choice.split(":", 2)
        if len(parts) >= 2:
            filepath = parts[0]
            try:
                lineno = int(parts[1])
            except ValueError:
                lineno = None
        else:
            filepath = choice
            lineno = None

        target = os.path.join(context.cwd, filepath)
        context.open_file(target, line=lineno)

class IDETools(ThingTools):
    name = "IDE / Editor"
    priority = 42

    def detect(self, cwd, system_info):
        # Show if ANY editor is available
        return any(shutil.which(x) for x in [
            "code", "zed", "cursor", "subl", "sublime_text",
            "nvim", "vim", "nano"
        ])

    def tools(self, context):
        return [
            IDEOpenFolderTool(),
            IDEOpenFileTool(),
        ]


def _detect_preferred_editor():
    for ed in ["code", "zed", "cursor", "subl", "sublime_text", "nvim", "vim", "nano"]:
        if shutil.which(ed):
            return ed
    return None


class IDEOpenFolderTool(ThingToolsTool):
    label = "Open Folder in IDE"
    hotkey = "o"
    description = "Launch this directory in a graphical or terminal IDE."

    def run(self, context):
        editor = _detect_preferred_editor()
        if not editor:
            context.notify("No IDE or editor found on system.")
            return

        cwd = context.cwd
        context.notify(f"Launching {editor} …")
        context.run_interactive(f"{editor} {shlex.quote(cwd)}")


class IDEOpenFileTool(ThingToolsTool):
    label = "Open Selected File in IDE"
    hotkey = "e"
    description = "Open the currently highlighted file in the IDE."

    def enabled(self, context):
        entry = context.current_selection()
        return entry and os.path.isfile(os.path.join(context.cwd, entry.name))

    def run(self, context):
        editor = _detect_preferred_editor()
        if not editor:
            context.notify("No IDE or editor found.")
            return

        entry = context.current_selection()
        if not entry:
            context.notify("No file selected.")
            return

        target = os.path.join(context.cwd, entry.name)
        context.notify(f"Launching {editor} …")
        context.run_interactive(f"{editor} {shlex.quote(target)}")

class PythonTools(ThingTools):
    name = "Python"
    priority = 45

    def detect(self, cwd, system_info):
        # enable always; fallback paths handled internally
        return True

    def tools(self, context):
        return [
            PythonReplTool(),
            PythonReplAutoreloadTool(),
            PythonReplPdbTool(),
            PythonReplFullDevTool(),
            PythonRunFileTool(),
            PythonDebugFileTool(),
        ]


def best_python_command():
    # Prefer uv run if installed
    if shutil.which("uv"):
        return "uv run"
    # prefer python3 over python
    if shutil.which("python3"):
        return "python3"
    return "python"


def best_ipython_command():
    # prefer ipython3 over ipython
    if shutil.which("ipython3"):
        return "ipython3"
    if shutil.which("ipython"):
        return "ipython"
    return None


class PythonReplTool(ThingToolsTool):
    label = "Python REPL"
    hotkey = "p"
    description = "Start Python or uv-run Python REPL."

    def run(self, context):
        cmd = best_python_command()
        context.run_interactive(cmd)


class PythonReplAutoreloadTool(ThingToolsTool):
    label = "IPython REPL (autoreload)"
    hotkey = "a"
    description = "Start IPython with autoreload active."

    def enabled(self, context):
        return best_ipython_command() is not None

    def run(self, context):
        ip = best_ipython_command()
        # %autoreload 2 ensures modules reload on change
        context.run_interactive(f"{ip} -c 'import IPython; IPython.start_ipython(argv=[\"--quick\", \"-i\", \"-c\", \"%autoreload 2\"] )'")


class PythonReplPdbTool(ThingToolsTool):
    label = "IPython REPL (pdb on)"
    hotkey = "d"
    description = "Start IPython with %pdb on."

    def enabled(self, context):
        return best_ipython_command() is not None

    def run(self, context):
        ip = best_ipython_command()
        context.run_interactive(f"{ip} -c 'import IPython; IPython.start_ipython(argv=[\"--quick\", \"-i\", \"-c\", \"%pdb on\"] )'")


class PythonReplFullDevTool(ThingToolsTool):
    label = "IPython REPL (autoreload + pdb)"
    hotkey = "v"
    description = "Start IPython with both autoreload and pdb enabled."

    def enabled(self, context):
        return best_ipython_command() is not None

    def run(self, context):
        ip = best_ipython_command()
        context.run_interactive(
            f"{ip} -c 'import IPython; IPython.start_ipython(argv=[\"--quick\", \"-i\", \"-c\", \"%autoreload 2\", \"-c\", \"%pdb on\"] )'"
        )


class PythonRunFileTool(ThingToolsTool):
    label = "Run Python File"
    hotkey = "r"
    description = "Pick a .py file and run it."

    def run(self, context):
        py_files = [f for f in os.listdir(context.cwd) if f.endswith(".py")]
        if not py_files:
            context.notify("No .py files in this directory.")
            return

        choice = context.list_menu(py_files, title="Select script to run:")
        if not choice:
            return

        cmd = best_python_command()
        target = os.path.join(context.cwd, choice)
        context.run_interactive(f"{cmd} {shlex.quote(target)}")


class PythonDebugFileTool(ThingToolsTool):
    label = "Debug Python File (pdb)"
    hotkey = "b"
    description = "Run script with pdb debugger."

    def run(self, context):
        py_files = [f for f in os.listdir(context.cwd) if f.endswith(".py")]
        if not py_files:
            context.notify("No .py files in this directory.")
            return

        choice = context.list_menu(py_files, title="Select script to debug:")
        if not choice:
            return

        cmd = best_python_command()
        target = os.path.join(context.cwd, choice)
        context.run_interactive(f"{cmd} -m pdb {shlex.quote(target)}")


class DiskTools(ThingTools):
    name = "Disk & Storage"
    priority = 50

    def detect(self, cwd, system_info):
        # Always show this group. Each tool individually checks for binary availability.
        return True

    def tools(self, context):
        return [
            DiskUsageBrowserTool(),
            DiskFilesystemUsageTool(),
            DiskPartitionInfoTool(),
            DiskSmartStatusTool(),
        ]

class DiskUsageBrowserTool(ThingToolsTool):
    label = "Browse Disk Usage (ncdu)"
    hotkey = "u"
    description = "Interactive folder size exploration."

    def enabled(self, context):
        return shutil.which("ncdu") is not None or shutil.which("du") is not None

    def run(self, context):
        if shutil.which("ncdu"):
            # ncdu is interactive → leave curses
            context.run_interactive("ncdu " + shlex.quote(context.cwd))
        else:
            # fallback: run du and show in scrollable preview
            out = context.run_capture("du -h --max-depth=1", cwd=context.cwd)
            context.text_preview_dialog(out, title="Directory Sizes (fallback du)")

class DiskFilesystemUsageTool(ThingToolsTool):
    label = "Disk Space Overview (df -h)"
    hotkey = "d"
    description = "Show total / used / free space per mounted filesystem."

    def run(self, context):
        output = context.run_capture("df -h --output=source,fstype,size,used,avail,pcent,target")
        context.text_preview_dialog(output, title="df -h")


class DiskPartitionInfoTool(ThingToolsTool):
    label = "Partition & Mount Info (lsblk)"
    hotkey = "p"
    description = "View block devices, partitions, and mountpoints."

    def enabled(self, context):
        return shutil.which("lsblk") is not None

    def run(self, context):
        output = context.run_capture("lsblk -f")
        context.text_preview_dialog(output, title="lsblk")

class DiskSmartStatusTool(ThingToolsTool):
    label = "Disk Health (smartctl)"
    hotkey = "h"
    description = "Show SMART health for drives."
    
    def enabled(self, context):
        return shutil.which("smartctl") is not None

    def run(self, context):
        # List available disks
        ls = context.run_capture("lsblk -ndo NAME,TYPE | awk '$2==\"disk\"{print $1}'")
        disks = [d.strip() for d in ls.splitlines() if d.strip()]
        if not disks:
            context.notify("No block disks found.")
            return

        choice = context.list_menu(disks, title="Select disk for SMART status:")
        if not choice:
            return

        context.run_interactive(f"sudo smartctl -a /dev/{choice}")

class GDBTools(ThingTools):
    label = "GDB Debugging"

    def available(cls, context):
        return context.which("gdb") is not None


class GDBRun(ThingToolsTool):
    label = "Run a binary under gdb"

    def run(self, context: ThingToolsToolContext):
        binary = context.path_input("Binary to debug:")
        if not binary:
            return
        context.run_interactive(["gdb", "--args", binary])


class GDBAttach(ThingToolsTool):
    label = "Attach to running process"

    def run(self, context):
        ps = context.capture("ps -eo pid,comm")
        pid = context.list_menu("Select process:", ps.splitlines())
        if not pid:
            return
        pid = pid.strip().split()[0]
        context.run_interactive(["gdb", "-p", pid])


class GDBCore(ThingToolsTool):
    label = "Debug core file"

    def run(self, context):
        binary = context.path_input("Binary:")
        core = context.path_input("Core file:")
        if binary and core:
            context.run_interactive(["gdb", binary, core])

class ValgrindTools(ThingTools):
    label = "Valgrind Analysis"

    def available(cls, context):
        return context.which("valgrind") is not None


class VGLeakCheck(ThingToolsTool):
    label = "Memory leak analysis (memcheck)"

    def run(self, context):
        binary = context.path_input("Binary:")
        if not binary:
            return
        context.run_interactive([
            "valgrind", "--leak-check=full", "--show-leak-kinds=all", binary
        ])


class VGRaceCheck(ThingToolsTool):
    label = "Data race analysis (helgrind)"

    def run(self, context):
        binary = context.path_input("Binary:")
        if not binary:
            return
        context.run_interactive(["valgrind", "--tool=helgrind", binary])


class VGHeapProfile(ThingToolsTool):
    label = "Heap profiling (massif)"

    def run(self, context):
        binary = context.path_input("Binary:")
        out = context.tempfile("massif.out.")
        context.run_interactive(["valgrind", "--tool=massif", f"--massif-out-file={out}", binary])
        context.text_preview("Massif Output Path", out)
        
        



class OwnershipTools(ThingTools):
    name = "Ownership & Permissions"
    priority = 60  # lower priority, appears near bottom

    def detect(self, cwd, system_info):
        # Always show, no special detection needed
        return True

    def tools(self, context):
        return [
            ViewFileSecurityInfoTool(),
            ChangeFileOwnerTool(),
            ChangeFileGroupTool(),
            ChangeFilePermissionsTool(),
            MakeExecutableTool(),
            MakeReadOnlyTool(),
        ]


class PortableObjectTools(ThingTools):
    name = "Portable Object Tools"
    priority = 44

    def detect(self, cwd, system_info):
        # Show this group if any of the useful binaries exist
        tools = ("file", "ldd", "readelf", "objdump", "nm", "wine")
        for t in tools:
            if shutil.which(t):
                return True
        return False

    def tools(self, context):
        return [
            InspectELF(),
            DisassembleELF(),
            ListSymbols(),
            RunWithLDPreload(),
            TraceLibraryLoads(),
            WineRunWithOverride(),
            InspectPE(),
        ]


# ----------------------------- Helpers -----------------------------
def _which_any(*names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def _safe_cmd_output(cmd):
    try:
        return subprocess.getoutput(cmd)
    except Exception as e:
        return f"[Error running {cmd}: {e}]"


# ----------------------------- Tools -----------------------------
class InspectELF(ThingToolsTool):
    label = "Inspect ELF / Shared Object"
    hotkey = "i"
    description = "Show file, ldd deps, and readelf header for a .so or binary."

    def run(self, context):
        path = context.input_prompt("Path to ELF binary / .so:")
        if not path:
            return
        path = os.path.expanduser(path)
        if not os.path.exists(path):
            context.notify("Path not found.")
            return

        parts = []
        # file
        if _which_any("file"):
            parts.append(f"--- file ---\n{_safe_cmd_output(shlex.join(['file', '--mime-type', '-b', path]))}\n")
        # ldd
        if shutil.which("ldd"):
            parts.append(f"--- ldd (dependencies) ---\n{_safe_cmd_output(shlex.join(['ldd', path]))}\n")
        else:
            parts.append("--- ldd ---\n[ldd not available]\n")
        # readelf (headers)
        if shutil.which("readelf"):
            parts.append(f"--- readelf -h ---\n{_safe_cmd_output(shlex.join(['readelf', '-h', path]))}\n")
            parts.append(f"--- readelf -s (symbols) ---\n{_safe_cmd_output(shlex.join(['readelf', '-s', path]))}\n")
        else:
            parts.append("--- readelf ---\n[readelf not available]\n")

        context.text_preview("\n".join(parts), title=f"Inspect: {os.path.basename(path)}")


class DisassembleELF(ThingToolsTool):
    label = "Disassemble (objdump)"
    hotkey = "d"
    description = "Run objdump -d on a binary or .so (beware very large output)."

    def enabled(self, context):
        return shutil.which("objdump") is not None

    def run(self, context):
        path = context.input_prompt("Binary or .so to disassemble:")
        if not path:
            return
        path = os.path.expanduser(path)
        if not os.path.exists(path):
            context.notify("Path not found.")
            return

        # Offer a choice of disassembly modes
        choice = context.list_menu(
            ["Full disassembly (objdump -d)", "Surface symbols + sections (objdump -x)", "Disassemble .text only (objdump -d -j .text)"],
            title="Disassembly mode"
        )
        if not choice:
            return

        if "Full" in choice:
            cmd = f"objdump -d {shlex.quote(path)}"
        elif "Surface" in choice:
            cmd = f"objdump -x {shlex.quote(path)}"
        else:
            cmd = f"objdump -d -j .text {shlex.quote(path)}"

        # objdump output can be huge; show with command preview (which uses subprocess.getoutput and text preview)
        context.run_command_preview(cmd)


class ListSymbols(ThingToolsTool):
    label = "List Exported / Dynamic Symbols (nm / readelf)"
    hotkey = "s"
    description = "Show exported symbols via nm -D or readelf -s."

    def enabled(self, context):
        return shutil.which("nm") or shutil.which("readelf")

    def run(self, context):
        path = context.input_prompt("Binary / .so to list symbols:")
        if not path:
            return
        path = os.path.expanduser(path)
        if not os.path.exists(path):
            context.notify("Path not found.")
            return

        if shutil.which("nm"):
            cmd = f"nm -D {shlex.quote(path)}"
            context.run_command_preview(cmd)
        elif shutil.which("readelf"):
            cmd = f"readelf -s {shlex.quote(path)}"
            context.run_command_preview(cmd)
        else:
            context.notify("Neither nm nor readelf available.")


class RunWithLDPreload(ThingToolsTool):
    label = "Run with LD_PRELOAD"
    hotkey = "l"
    description = "Run a program with LD_PRELOAD set to the provided .so (interactive)."

    def run(self, context):
        binary = context.input_prompt("Binary to run (full path or relative):")
        if not binary:
            return
        binary = os.path.expanduser(binary)
        if not os.path.exists(binary):
            context.notify("Binary not found.")
            return

        pre = context.input_prompt("Library to LD_PRELOAD (full path to .so):")
        if not pre:
            return
        pre = os.path.expanduser(pre)
        if not os.path.exists(pre):
            context.notify("Library not found.")
            return

        # Build an sh-friendly invocation to preserve environment
        cmd = f"LD_PRELOAD={shlex.quote(pre)} {shlex.quote(binary)}"
        context.notify(f"Running with LD_PRELOAD={pre}")
        context.run_interactive(cmd)


class TraceLibraryLoads(ThingToolsTool):
    label = "Trace library loads (LD_DEBUG=libs)"
    hotkey = "t"
    description = "Run a binary with LD_DEBUG=libs to see how the loader resolves shared objects."

    def run(self, context):
        binary = context.input_prompt("Binary to trace:")
        if not binary:
            return
        binary = os.path.expanduser(binary)
        if not os.path.exists(binary):
            context.notify("Binary not found.")
            return

        cmd = f"LD_DEBUG=libs {shlex.quote(binary)}"
        context.notify("Running with LD_DEBUG=libs (may be very verbose).")
        context.run_interactive(cmd)


class WineRunWithOverride(ThingToolsTool):
    label = "Run EXE with WINEDLLOVERRIDES (wine)"
    hotkey = "w"
    description = "Run a Windows exe under wine with optional DLL override string."

    def enabled(self, context):
        return shutil.which("wine") is not None

    def run(self, context):
        if not shutil.which("wine"):
            context.notify("wine not installed.")
            return

        exe = context.input_prompt("Path to Windows EXE/DLL:")
        if not exe:
            return
        exe = os.path.expanduser(exe)
        if not os.path.exists(exe):
            context.notify("Path not found.")
            return

        override = context.input_prompt("WINEDLLOVERRIDES string (e.g. comctl32=native,builtin):")
        if override is None:
            return  # canceled

        if override.strip():
            cmd = f"WINEDLLOVERRIDES={shlex.quote(override)} wine {shlex.quote(exe)}"
        else:
            cmd = f"wine {shlex.quote(exe)}"

        context.notify(f"Running under wine: {exe}")
        context.run_interactive(cmd)


class InspectPE(ThingToolsTool):
    label = "Inspect Windows PE (file / objdump)"
    hotkey = "p"
    description = "Basic PE analysis using file and objdump -x (if available)."

    def run(self, context):
        pe = context.input_prompt("Path to EXE or DLL:")
        if not pe:
            return
        pe = os.path.expanduser(pe)
        if not os.path.exists(pe):
            context.notify("Path not found.")
            return

        parts = []
        if shutil.which("file"):
            parts.append(f"--- file ---\n{_safe_cmd_output(shlex.join(['file', pe]))}\n")
        if shutil.which("objdump"):
            parts.append(f"--- objdump -x ---\n{_safe_cmd_output(shlex.join(['objdump', '-x', pe]))}\n")
        else:
            parts.append("[objdump not available]\n")

        context.text_preview("\n".join(parts), title=f"PE Inspect: {os.path.basename(pe)}")


class ViewFileSecurityInfoTool(ThingToolsTool):
    label = "View Ownership & Permissions"
    hotkey = "i"
    description = "Show owner, group, mode, and ACLs if available."

    def enabled(self, context):
        return context.selected_file_path is not None

    def run(self, context):
        path = context.selected_file_path
        if not path:
            return
        output = context.run_capture(f"stat {shlex.quote(path)} 2>&1")
        context.text_preview_dialog(output, title="File Security Info")


class ChangeFileOwnerTool(ThingToolsTool):
    label = "Change Owner"
    hotkey = "o"
    description = "Set a new owner for this file."

    def enabled(self, context):
        return context.selected_file_path is not None

    def run(self, context):
        path = context.selected_file_path
        user = context.input_prompt("New owner username:")
        if not user:
            return
        if not context.confirm(f"Apply: chown {user} {path}?"):
            return
        result = context.run_capture(f"chown {shlex.quote(user)} {shlex.quote(path)} 2>&1")
        context.text_preview_dialog(result or "Done.", title="chown result")


class ChangeFileGroupTool(ThingToolsTool):
    label = "Change Group"
    hotkey = "g"
    description = "Set a new group for this file."

    def enabled(self, context):
        return context.selected_file_path is not None

    def run(self, context):
        path = context.selected_file_path
        group = context.input_prompt("New group name:")
        if not group:
            return
        if not context.confirm(f"Apply: chgrp {group} {path}?"):
            return
        result = context.run_capture(f"chgrp {shlex.quote(group)} {shlex.quote(path)} 2>&1")
        context.text_preview_dialog(result or "Done.", title="chgrp result")


class ChangeFilePermissionsTool(ThingToolsTool):
    label = "Change Permissions (chmod)"
    hotkey = "m"
    description = "Set file mode (e.g., 644, 755, u+rw)."

    def enabled(self, context):
        return context.selected_file_path is not None

    def run(self, context):
        path = context.selected_file_path
        mode = context.input_prompt("Enter mode (e.g., 644, u+rw):")
        if not mode:
            return
        if not context.confirm(f"Apply: chmod {mode} {path}?"):
            return
        result = context.run_capture(f"chmod {shlex.quote(mode)} {shlex.quote(path)} 2>&1")
        context.text_preview_dialog(result or "Done.", title="chmod result")


class MakeExecutableTool(ThingToolsTool):
    label = "Make Executable"
    hotkey = "x"
    description = "Run: chmod u+x <file>"

    def enabled(self, context):
        return context.selected_file_path is not None

    def run(self, context):
        path = context.selected_file_path
        if not context.confirm(f"Apply: chmod u+x {path}?"):
            return
        result = context.run_capture(f"chmod u+x {shlex.quote(path)} 2>&1")
        context.text_preview_dialog(result or "Done.", title="chmod u+x result")


class MakeReadOnlyTool(ThingToolsTool):
    label = "Make Read-Only"
    hotkey = "r"
    description = "Remove write permission: chmod a-w <file>"

    def enabled(self, context):
        return context.selected_file_path is not None

    def run(self, context):
        path = context.selected_file_path
        if not context.confirm(f"Apply: chmod a-w {path}?"):
            return
        result = context.run_capture(f"chmod a-w {shlex.quote(path)} 2>&1")
        context.text_preview_dialog(result or "Done.", title="chmod a-w result")
        
import os
import json
import subprocess
import urllib.request
import urllib.error

try:
    import boto3
except ImportError:
    boto3 = None



# WasmTools - a ThingTools group for WebAssembly analysis, disassembly, conversion, and execution.
# Drop into your existing ThingTools/ThingToolsTool ecosystem.
#
# This mirrors the structure used in PortableObjectTools.

import os
import shlex
import shutil
import subprocess

# from notals.tools_base import ThingTools, ThingToolsTool, ThingToolsToolContext
# Assume ThingTools, ThingToolsTool, ThingToolsToolContext are already provided.

class WasmTools(ThingTools):
    name = "WebAssembly Tools"
    priority = 45

    def detect(self, cwd, system_info):
        # Show this menu if any wasm-related tool is present
        return any(shutil.which(t) for t in (
            "wasm-objdump", "wasm2wat", "wat2wasm", "wasm-ld", "wasmtime", "wasmer"
        ))

    def tools(self, context):
        return [
            InspectWasm(),
            DisassembleWasmObjdump(),
            ConvertWasmToWat(),
            ConvertWatToWasm(),
            WasmRunWasmtime(),
            WasmRunWasmer(),
        ]


def _exists(path):
    p = os.path.expanduser(path)
    return p if os.path.exists(p) else None


def _run_capture(cmd):
    try:
        return subprocess.getoutput(cmd)
    except Exception as e:
        return f"[Error running {cmd}: {e}]"


class InspectWasm(ThingToolsTool):
    label = "Inspect WebAssembly module (file + size + sections)"
    hotkey = "i"

    def run(self, context):
        path = context.input_prompt("WASM file (.wasm):")
        if not path:
            return
        path = _exists(path)
        if not path:
            context.notify("File not found.")
            return

        parts = []

        # file
        if shutil.which("file"):
            parts.append("--- file ---\n" + _run_capture(shlex.join(["file", path])) + "\n")

        # wasm-objdump -x (for section headers)
        if shutil.which("wasm-objdump"):
            parts.append("--- wasm-objdump -x ---\n" +
                          _run_capture(shlex.join(["wasm-objdump", "-x", path])) + "\n")
        else:
            parts.append("[wasm-objdump not available]\n")

        context.text_preview("\n".join(parts), title=f"WASM Inspect: {os.path.basename(path)}")


class DisassembleWasmObjdump(ThingToolsTool):
    label = "Disassemble WASM (wasm-objdump -d)"
    hotkey = "d"

    def enabled(self, context):
        return shutil.which("wasm-objdump") is not None

    def run(self, context):
        path = context.input_prompt("WASM file to disassemble:")
        if not path:
            return
        path = _exists(path)
        if not path:
            context.notify("File not found.")
            return

        cmd = shlex.join(["wasm-objdump", "-d", path])
        context.run_command_preview(cmd)


class ConvertWasmToWat(ThingToolsTool):
    label = "Convert .wasm → .wat (wasm2wat)"
    hotkey = "w"

    def enabled(self, context):
        return shutil.which("wasm2wat") is not None

    def run(self, context):
        path = context.input_prompt("Input .wasm:")
        if not path:
            return
        path = _exists(path)
        if not path:
            context.notify("File not found.")
            return

        out = context.input_prompt("Output .wat (optional; default same name):")
        if not out:
            out = os.path.splitext(path)[0] + ".wat"

        cmd = shlex.join(["wasm2wat", path, "-o", out])
        context.run_command_preview(cmd)


class ConvertWatToWasm(ThingToolsTool):
    label = "Convert .wat → .wasm (wat2wasm)"
    hotkey = "a"

    def enabled(self, context):
        return shutil.which("wat2wasm") is not None

    def run(self, context):
        path = context.input_prompt("Input .wat:")
        if not path:
            return
        path = _exists(path)
        if not path:
            context.notify("File not found.")
            return

        out = context.input_prompt("Output .wasm (optional; default same name):")
        if not out:
            out = os.path.splitext(path)[0] + ".wasm"

        cmd = shlex.join(["wat2wasm", path, "-o", out])
        context.run_command_preview(cmd)


class WasmRunWasmtime(ThingToolsTool):
    label = "Run WASM with wasmtime"
    hotkey = "m"

    def enabled(self, context):
        return shutil.which("wasmtime") is not None

    def run(self, context):
        path = context.input_prompt("WASM module to run:")
        if not path:
            return
        path = _exists(path)
        if not path:
            context.notify("File not found.")
            return

        # Support passing arguments
        args = context.input_prompt("Arguments (optional):")
        if args:
            cmd = f"wasmtime {shlex.quote(path)} -- {args}"
        else:
            cmd = f"wasmtime {shlex.quote(path)}"

        context.run_interactive(cmd)


class WasmRunWasmer(ThingToolsTool):
    label = "Run WASM with wasmer"
    hotkey = "r"

    def enabled(self, context):
        return shutil.which("wasmer") is not None

    def run(self, context):
        path = context.input_prompt("WASM module to run:")
        if not path:
            return
        path = _exists(path)
        if not path:
            context.notify("File not found.")
            return

        args = context.input_prompt("Arguments (optional):")
        if args:
            cmd = f"wasmer run {shlex.quote(path)} -- {args}"
        else:
            cmd = f"wasmer run {shlex.quote(path)}"

        context.run_interactive(cmd)


class GPUTools(ThingTools):
    name = "GPU Tools"
    priority = 46

    def detect(self, cwd, system_info):
        # Visibility triggered only if at least one GPU-related command exists
        return any(
            shutil.which(x) for x in (
                "nvidia-smi",
                "rocm-smi",
                "glxinfo",
                "vulkaninfo",
                "clinfo"
            )
        )

    def tools(self, context):
        return [
            GPUListNvidia(),
            GPUListRocm(),
            GPUVulkanInfo(),
            GPUOpenGLInfo(),
            GPUOpenCLInfo(),
        ]


class GPUListNvidia(ThingToolsTool):
    label = "NVIDIA GPU Info (nvidia-smi)"
    hotkey = "n"

    def enabled(self, context):
        return shutil.which("nvidia-smi") is not None

    def run(self, context):
        cmd = "nvidia-smi -q -x" if context.confirm("Use full XML detail?") else "nvidia-smi"
        context.run_command_preview(cmd)


class GPUListRocm(ThingToolsTool):
    label = "AMD ROCm GPU Info (rocm-smi)"
    hotkey = "r"

    def enabled(self, context):
        return shutil.which("rocm-smi") is not None

    def run(self, context):
        cmd = "rocm-smi --showproductname --showid --showhw --showfan --showtemp --showvoltage --showpower"
        context.run_command_preview(cmd)


class GPUVulkanInfo(ThingToolsTool):
    label = "Vulkan Devices (vulkaninfo)"
    hotkey = "v"

    def enabled(self, context):
        return shutil.which("vulkaninfo") is not None

    def run(self, context):
        detail = context.confirm("Full vulkaninfo? (may be long)") 
        cmd = "vulkaninfo" if detail else "vulkaninfo | head -200"
        context.run_command_preview(cmd)


class GPUOpenGLInfo(ThingToolsTool):
    label = "OpenGL Renderer Info (glxinfo)"
    hotkey = "g"

    def enabled(self, context):
        return shutil.which("glxinfo") is not None

    def run(self, context):
        # extract renderer block only
        cmd = "glxinfo | grep -E 'OpenGL vendor|OpenGL renderer|OpenGL core profile version'"
        context.run_command_preview(cmd)


class GPUOpenCLInfo(ThingToolsTool):
    label = "OpenCL Platform/Device Info (clinfo)"
    hotkey = "c"

    def enabled(self, context):
        return shutil.which("clinfo") is not None

    def run(self, context):
        # clinfo output is usually large; show in preview
        context.run_command_preview("clinfo")

# NotalAliasTools - lets user create a shell alias or launcher script for the current session.
# This intentionally keeps namespace minimal and does not import extra helpers.

import os
import shlex
import shutil
import subprocess

# Assumes ThingTools, ThingToolsTool, ThingToolsToolContext already exist.

class NotalAliasTools(ThingTools):
    name = "Alias / Launcher Setup"
    priority = 47

    def detect(self, cwd, system_info):
        # Always safe to show; no required dependencies
        return True

    def tools(self, context):
        return [
            CreateRuntimeAlias(),
            CreateShellRCEntry(),
            CreateLocalLauncherScript(),
        ]


class CreateRuntimeAlias(ThingToolsTool):
    label = "Create alias for this session (shell-only)"
    hotkey = "a"

    def run(self, context):
        # Determine executable invocation
        script = context.program_path or "python3 notals.py"
        alias_name = context.input_prompt("Alias name (default: notals):") or "notals"

        cmd = f"alias {alias_name}={shlex.quote(script)}"

        context.notify(f"Run this in *your shell* to activate now:\n\n{cmd}\n")

        # Optionally auto-inject if running inside an interactive shell under context.run_interactive
        if context.confirm("Inject into current shell session? (Only works if using a shell launched from this tool)"):
            context.run_interactive(cmd)


class CreateShellRCEntry(ThingToolsTool):
    label = "Add alias to ~/.bashrc or ~/.zshrc"
    hotkey = "r"

    def run(self, context):
        script = context.program_path or "python3 notals.py"
        alias_name = context.input_prompt("Alias name (default: notals):") or "notals"
        line = f"alias {alias_name}={shlex.quote(script)}"

        shell = os.environ.get("SHELL", "")
        if "zsh" in shell:
            rc = os.path.expanduser("~/.zshrc")
        else:
            rc = os.path.expanduser("~/.bashrc")

        if not context.confirm(f"Append to {rc}?"):
            return

        try:
            with open(rc, "a") as f:
                f.write("\n" + line + "\n")
            context.notify(f"Added alias to {rc}\nOpen new shell or run: source {rc}")
        except Exception as e:
            context.notify(f"Failed to write: {e}")


class CreateLocalLauncherScript(ThingToolsTool):
    label = "Create local run script (./notals)"
    hotkey = "s"

    def run(self, context):
        script = context.program_path or "python3 notals.py"
        out = context.input_prompt("Script name (default: notals):") or "notals"
        out = os.path.abspath(out)

        try:
            with open(out, "w") as f:
                f.write(f"#!/usr/bin/env sh\nexec {script} \"$@\"\n")
            os.chmod(out, 0o755)
            context.notify(f"Created launcher script: {out}")
        except Exception as e:
            context.notify(f"Error: {e}")
            
# GloatTools - a fun tools group to "flex" environment aesthetics and system stats
# Works in your ThingTools ecosystem (ThingTools / ThingToolsTool / ThingToolsToolContext).

import shutil
import shlex

class GloatTools(ThingTools):
    name = "Gloat / Show-Off Tools"
    priority = 48

    def detect(self, cwd, system_info):
        # Only show if at least *one* of these commands exists
        return any(
            shutil.which(cmd) for cmd in (
                "neofetch", "fastfetch", "ufetch",
                "btop", "htop", "bpytop", "gotop"
            )
        )

    def tools(self, context):
        return [
            GloatNeofetch(),
            GloatFastfetch(),
            GloatUfetch(),
            GloatBtop(),
            GloatHtop(),
            GloatBpytop(),
            GloatGotop(),
        ]


class GloatNeofetch(ThingToolsTool):
    label = "Flex system with neofetch"
    hotkey = "n"

    def enabled(self, context):
        return shutil.which("neofetch") is not None

    def run(self, context):
        context.run_interactive("neofetch")


class GloatFastfetch(ThingToolsTool):
    label = "Flex system with fastfetch"
    hotkey = "f"

    def enabled(self, context):
        return shutil.which("fastfetch") is not None

    def run(self, context):
        context.run_interactive("fastfetch")


class GloatUfetch(ThingToolsTool):
    label = "Tiny minimal flex (ufetch)"
    hotkey = "u"

    def enabled(self, context):
        return shutil.which("ufetch") is not None

    def run(self, context):
        context.run_interactive("ufetch")


class GloatBtop(ThingToolsTool):
    label = "Show fancy live resources (btop)"
    hotkey = "b"

    def enabled(self, context):
        return shutil.which("btop") is not None

    def run(self, context):
        context.run_interactive("btop")


class GloatHtop(ThingToolsTool):
    label = "Show live processes (htop)"
    hotkey = "h"

    def enabled(self, context):
        return shutil.which("htop") is not None

    def run(self, context):
        context.run_interactive("htop")


class GloatBpytop(ThingToolsTool):
    label = "Show live resources (bpytop)"
    hotkey = "p"

    def enabled(self, context):
        return shutil.which("bpytop") is not None

    def run(self, context):
        context.run_interactive("bpytop")


class GloatGotop(ThingToolsTool):
    label = "Go-powered live monitor (gotop)"
    hotkey = "g"

    def enabled(self, context):
        return shutil.which("gotop") is not None

    def run(self, context):
        context.run_interactive("gotop")


EXTRA_TOOLS = [
    PortDiscoveryTools,
    HttpServeTools,
    SearchTools,
    IDETools,
    PythonTools,
    DiskTools,
    PortableObjectTools,
    WasmTools,
    GPUTools,
    NotalAliasTools,
    OwnershipTools,
    # add GDBTools, ValgrindTools after fixing their interfaces
]

