# not-a-ls 

notals.py (not-a-ls -- it's not nautilus & it's not ls!)

**notals** (styled not-a-ls if you please) is a WIP un-orthodox (navigational, no Miller columns here) terminal file manager designed for people who live in the shell but want the convenience of a graphical project navigator that has double clicking and context menus and breadcrumb navigation but is usable over SSH with no X forwarding. It offers fast tree navigation, fuzzy search, direct warping, safe previews, drag and drop, batch move/copy via a staging pouch, undo for filesystem operations, and optional project-aware command palettes.

It is built on `curses` and `python3` and runs inside a modern Linux terminal. Maybe it's more like the `nano` that straddles the `nautilus`-`ls` spectrum.

  ### Warning: Very experimental file manager esp on mounts - run only in ephemeral Docker containers or VMs you expect to lose!

---

## Features

- **Directory browser** with folders and files displayed in structured view.
- **Fuzzy filter mode** (`f`) for rapid search inside a directory.
- **Breadcrumb navigation** (`h`) to jump up the directory tree quickly.
- **Safe file previews** that avoid accidental execution or mutation.
- **Context-sensitive project detection**:
  - Python virtualenvs
  - Node/npm projects
  - Rust Cargo projects
  - Go modules
  - Docker contexts
  - Kubernetes config directories
  - Flutter / React Native workspaces
- **Undo for move/copy** (`U`), backed by a persistent log (redo planned).
- **"Pouch" staging area** (`p`) for collecting items before batch move/copy.
- **Drag-and-drop inside the terminal** for rearranging directory structures.
- **Shell command runner** (`!`) ({} for selected pathsub) with explicit confirmation and path placeholders.


---

## Key Bindings

| Action | Keys |
|-------|------|
| Quit | `q` or `ESC` |
| Enter directory / preview file | `Enter` |
| Go up one directory | `u` |
| Go back (history) | `b` |
| Fuzzy filter mode | `f` |
| Breadcrumb navigation | `h` |
| Add selected item to pouch | `p` |
| Open pouch manager | `P` |
| Undo last operation | `U` |
| (debug) Print tool init timings | `Z` |
| Rename selected item | `R` |
| Delete selected item (to a trashfile) | `D` |
| Create new file or directory | `M` |
| Inspect selected file or directory | `i` |
| Run shell command on selected item | `!` |
| Project actions (if detected) | `a` |
| Jump to arbitrary path | `g` |

Additionally:  
- Mouse scroll moves view.  
- Click to select.  
- Drag to move items into folders or up to parent.  

---

## Safe File Preview Behavior

`open_safe(path)` attempts to preview without modifying files. It detects text, images, PDFs, archives, and executables. Certain system tools (`less`, `chafa`, `pdftotext`) may be used if installed, but only after explicit confirmation.


---

## Undo

All filesystem move/copy actions are logged (the intent, not in a journaling sense)
`U` restores the previous state.  

Undo works across directories and renames.

---

## Requirements

- Python 3.7.3+
- A terminal that supports `curses`
- Linux or macOS recommended

**Note for Windows users:**  
`curses` is not included in the default Windows Python build. To run notals on Windows, possibly use **WSL**, or install a third-party curses port (such as `windows-curses`):

Optionally install preview helpers:
a la `sudo apt install less chafa poppler-utils`

---

## Philosophy

The purpose of **notals** is to provide a file-management and project-navigation environment that fits the *developer who stays in the terminal* but not at the prompt. It aims to reduce context switching, allow exploratory browsing, and offer safety tools (undo, confirmations, staging) that are usually absent in shell workflows, while surfacing the usual suspects of terminal first tools to beginners.

It is not trying to replace your editor. It is trying to make all the space between files easier to move through, especially in an unfamiliar place you won't be for long, and where you want to be annoyed by default before breaking things.

---

## Roadmap

This project is evolving. Expect refinements to keybindings, menu grouping, state retention, and discovery logic as usage patterns become clearer.

### Planned Core Tool Groups (Default)

These are always enabled because they have minimal dependencies and are useful in nearly every environment.

| Tool Group | Purpose | Tools Included |
|-----------|---------|----------------|
| `SearchTools` | Locate files or search text within a project. Falls back cleanly if external tools are missing. | `FilenameSearchTool`, `ContentSearchTool` |
| `HttpServeTools` | Serve the current directory over HTTP for quick sharing or testing. | `HttpServeHereTool` |
| `PortDiscoveryTools` | Inspect open network ports and listening processes (`ss`, `lsof`, etc.). | `PortListTool`, `ListeningOnlyTool`, `PortProcessesTool` |
| `NotalAliasTools` | Create convenient launch aliases. | Quality-of-life; not required for operation. |
| `IDETools` | Open the current directory or selected file in a system editor (`code`, `vim`, etc.). | `IDEOpenFolderTool`, `IDEOpenFileTool` |
| `PythonTools` | Launch Python REPLs, run `.py` files, and debug interactively. | `PythonReplTool`, `PythonReplAutoreloadTool`, `PythonReplPdbTool`, `PythonReplFullDevTool`, `PythonRunFileTool`, `PythonDebugFileTool` |
| `DiskTools` | View disk usage, free space, and partitions (`df`, `lsblk`, optional `ncdu`). | `DiskUsageBrowserTool`, `DiskFilesystemUsageTool`, `DiskPartitionInfoTool`, `DiskSmartStatusTool` |

These form the stable base set: fast, low dependency, and always relevant.

---

### Planned Extra / Optional Tools (Opt-In)

Tools in this category provide additional power but are less universal, require external dependencies, or assume more advanced workflows.

| Tool Group | Purpose | Reason Not Default |
|-----------|---------|-------------------|
| `PortableObjectTools` | Inspect ELF binaries, linking, symbols, etc. | Specialized to systems / reverse-engineering workflows. |
| `WasmTools` | View and run `.wasm` / `.wat` modules. | Niche; requires external runtimes. |
| `GPUTools` | Query GPU details (`nvidia-smi`, `rocm-smi`, etc.). | Only relevant on GPU-capable hosts. |
| `OwnershipTools` | Change file owners, groups, and perms. | Potentially destructive; deliberately opt-in. |
| `GDBTools` / `ValgrindTools` | Debug and analyze complex binaries. | Advanced use; requires debug toolchain installs. |

---

### Cloud / Container / Orchestration Tools (Auto-Detected)

These groups only load when their environment indicators are present. They do **not** slow startup otherwise.

| Group | Environment Trigger | Purpose |
|------|---------------------|---------|
| `DockerTools` | Running inside a container | Inspect mounts, namespaces, logs; enter other containers. |
| `KubernetesTools` | ServiceAccount + API available | Pod identity, namespace listing, interactive exec/logs. |
| `EC2Tools` | EC2 metadata reachable | Show instance identity, EBS volumes, describe instance. |
| `ECSTools` | ECS Task metadata URI present | Show task membership, peer containers, ECS service details. |

These tools activate themselves only when relevant — otherwise they stay invisible.

## Understanding the Three “Systems for Action”

`not-a-ls` is built around *three different layers of action*.  
They interact, but each has a different scope and activation model.

### 1. Thing Tools (Global / Folder-Agnostic)

These appear in the **Tools menu**, independent of what folder you're browsing.

- They are grouped into **Tool Groups** (e.g., DockerTools, DiskTools, TextEditingTools).
- Each group defines:
  - A `detect()` method to decide whether it should be visible
  - A `tools(context)` method that returns the individual actions

Examples:

| Tool Group | Typical Actions | When It Appears |
|-----------|-----------------|----------------|
| `TextEditingTools` | Open or edit files with DumbEd included editor (a lighter nano for those slim python containers) | Always when a text file is selected |
| `DockerTools` | Enter other containers, inspect mounts | Only when running inside Docker |
| `EC2Tools` | Instance metadata and AWS details | Only on EC2 machines |

> These tools are **global utilities** that help you understand or manipulate the *system you're inside*.

---

### 2. Project / Special Folder Actions (Folder-Scoped)

Some directories represent meaningful workspaces.  
For example: a Python project, a Node project, a git repo, etc.

A folder becomes a **Project / Special Folder** when:
- Certain files or tags are detected (e.g., `pyproject.toml`, `.git`, `package.json`)


These folders get a **context-sensitive menu** of actions.

Examples:

| Folder Type | Detected By | Possible Menu Actions |
|------------|-------------|----------------------|
| Python Project | `pyproject.toml` or `.venv` | Run tests, open REPL, run app |
| Git Repository | `.git` | Commit, diff, branch browse |
| Web App | `package.json` or `vite.config` | Start dev server, install deps |

> These actions are **about the folder**, not the system.  
> They are the “project-aware” layer.

---

### 3. Smart Filetype Preview Actions (File-Scoped)

When you highlight a file, `not-a-ls` tries to **understand what it is**.

This enables:
- Syntax-aware previews
- File-specific actions (e.g., play a `.cast` file, extract a `.zip`, show EXIF for an image)
- Future user-defined behaviors

Examples:

| File Type | Smart Preview | Actions |
|----------|--------------|---------|
| `.cast` (asciinema) | Show metadata summary | “Replay recording” |
| `.md` | Render as plaintext | Edit, convert, open viewer |
| `.py` | Inspect imports | Run, debug, edit |
| Images | Show resolution, depth | View, optimize |

#### Future Customization (Planned)

Users may be able to register behavior via:
- A project-level `.notals.json`
- Environment variables like `NOTALS_FILETYPE_HOOKS`
- Plugin directories (`~/.config/notals/plugins/`)

This will allow:
- Custom preview commands
- Custom file actions (e.g., “Convert to WebP”, “Compile shader”)

> This layer is **file-centric**, focused on *what you're pointing at right now*.


---


## License

MIT. Experimental file managers are inherently dangerous & invite benevolent ext4undelete, photorec, and testdisk infestations. Use at your own risk!!
