# wgx for Windows

This directory contains the Windows port scaffold for wgx.

## Layout

- `Native/` contains the Windows native tunnel runner. It reuses the shared C
  WireGuard core from `../src`, loads `wintun.dll` dynamically, creates a Wintun
  adapter, configures interface addresses from a wg-quick `.conf`, and moves IP
  packets between Wintun and the wgx core.
- `Desktop/` contains the Windows desktop shell. It is a native Win32 C++ app
  with a macOS-like split view: tunnel list on the left, selected tunnel details
  on the right, and a Windows tray icon shown at startup.

## Runtime files

Put these files next to `wgx-ui.exe`:

- `wgx-win.exe`
- the matching architecture `wintun.dll` from `../wintun/bin/<arch>/wintun.dll`

Tunnel configs are stored under:

`%APPDATA%\wgx\tunnels`

## Build notes

Both the UI and tunnel runner are C/C++. The C core is still POSIX-shaped, so
the Windows targets are designed for MSYS2/MinGW where `winpthread`, `libuv`,
`libsodium`, and `c-ares` are available. The repository instruction says not to
compile here, so this directory only adds the port files.

The intended command is:

```sh
cmake -S . -B build -G Ninja
cmake --build build
```

To build only the native Win32 UI:

```sh
cmake -S Desktop -B Desktop/build -G Ninja
cmake --build Desktop/build
```

## Current behavior

The Win32 app can:

- show a tray icon immediately after startup;
- import `.conf` tunnels;
- list tunnels in the left sidebar;
- show interface, peer, DNS, endpoint, allowed IP, and latest log information;
- start and stop the selected tunnel by launching `wgx-win.exe`;
- keep status in sync with the native process lifetime.
