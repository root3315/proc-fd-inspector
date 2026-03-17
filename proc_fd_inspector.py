#!/usr/bin/env python3
"""
proc-fd-inspector - Inspect file descriptors of running processes on Linux.

This tool reads from /proc/<pid>/fd/ to show what files, sockets, pipes,
and other resources a process has open.
"""

import argparse
import os
import stat
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


PROC_ROOT = Path("/proc")


def get_all_pids():
    """Return a list of all numeric PIDs from /proc."""
    pids = []
    try:
        for entry in PROC_ROOT.iterdir():
            if entry.is_dir() and entry.name.isdigit():
                pids.append(int(entry.name))
    except PermissionError:
        pass
    return sorted(pids)


def get_process_name(pid):
    """Get the process name from /proc/<pid>/comm."""
    try:
        comm_path = PROC_ROOT / str(pid) / "comm"
        return comm_path.read_text().strip()
    except (PermissionError, FileNotFoundError, ProcessLookupError):
        return "<unknown>"


def get_process_cmdline(pid):
    """Get the full command line from /proc/<pid>/cmdline."""
    try:
        cmdline_path = PROC_ROOT / str(pid) / "cmdline"
        content = cmdline_path.read_bytes().decode("utf-8", errors="replace")
        return " ".join(content.split("\x00"))
    except (PermissionError, FileNotFoundError, ProcessLookupError):
        return "<unknown>"


def get_process_user(pid):
    """Get the UID of the process owner."""
    try:
        status_path = PROC_ROOT / str(pid) / "status"
        for line in status_path.read_text().splitlines():
            if line.startswith("Uid:"):
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]
    except (PermissionError, FileNotFoundError, ProcessLookupError):
        pass
    return "<unknown>"


def resolve_fd_target(fd_path):
    """Resolve a file descriptor to its target path or description."""
    try:
        target = os.readlink(fd_path)
        return target
    except (OSError, PermissionError):
        return "<unavailable>"


def classify_fd_type(target):
    """Classify the type of file descriptor based on its target."""
    if target.startswith("socket:"):
        return "socket"
    elif target.startswith("pipe:"):
        return "pipe"
    elif target.startswith("anon_inode:"):
        return "anon_inode"
    elif target.startswith("/dev/"):
        return "device"
    elif target.startswith("/"):
        return "file"
    elif target == "deleted":
        return "deleted"
    else:
        return "other"


def get_socket_info(target):
    """Extract socket information from target string."""
    if target.startswith("socket:["):
        inode = target[8:-1]
        return f"inode={inode}"
    return target


def get_pipe_info(target):
    """Extract pipe information from target string."""
    if target.startswith("pipe:["):
        inode = target[6:-1]
        return f"inode={inode}"
    return target


def inspect_pid_fds(pid, filter_type=None):
    """
    Inspect all file descriptors for a given PID.
    
    Returns a list of dicts with fd information.
    """
    fd_dir = PROC_ROOT / str(pid) / "fd"
    fds = []
    
    try:
        fd_entries = sorted(fd_dir.iterdir(), key=lambda x: int(x.name))
    except (PermissionError, FileNotFoundError, ProcessLookupError):
        return fds
    
    for fd_path in fd_entries:
        fd_num = fd_path.name
        target = resolve_fd_target(fd_path)
        fd_type = classify_fd_type(target)
        
        if filter_type and fd_type != filter_type:
            continue
        
        fd_info = {
            "fd": fd_num,
            "target": target,
            "type": fd_type,
        }
        
        if fd_type == "socket":
            fd_info["details"] = get_socket_info(target)
        elif fd_type == "pipe":
            fd_info["details"] = get_pipe_info(target)
        elif fd_type == "file":
            try:
                fd_stat = os.stat(fd_path)
                fd_info["size"] = fd_stat.st_size
                fd_info["mode"] = stat.filemode(fd_stat.st_mode)
            except (OSError, PermissionError):
                pass
        
        fds.append(fd_info)
    
    return fds


def format_fd_table(fds, show_all=False):
    """Format file descriptors as a table string."""
    if not fds:
        return "  No file descriptors found"
    
    lines = []
    lines.append("  FD   TYPE         TARGET")
    lines.append("  " + "-" * 60)
    
    for fd in fds:
        fd_num = fd["fd"]
        fd_type = fd["type"]
        target = fd["target"]
        
        if len(target) > 50 and not show_all:
            target = target[:47] + "..."
        
        lines.append(f"  {fd_num:<6} {fd_type:<12} {target}")
    
    return "\n".join(lines)


def list_processes(search_term=None, user_filter=None):
    """List all processes with optional filtering."""
    processes = []
    
    for pid in get_all_pids():
        try:
            name = get_process_name(pid)
            cmdline = get_process_cmdline(pid)
            uid = get_process_user(pid)
            
            if search_term and search_term.lower() not in name.lower():
                continue
            
            if user_filter and uid != user_filter:
                continue
            
            processes.append({
                "pid": pid,
                "name": name,
                "cmdline": cmdline,
                "uid": uid,
            })
        except (PermissionError, ProcessLookupError):
            continue
    
    return processes


def print_process_list(search_term=None, user_filter=None):
    """Print a formatted list of processes."""
    procs = list_processes(search_term, user_filter)
    
    if not procs:
        print("No matching processes found.")
        return
    
    print(f"{'PID':<8} {'UID':<8} {'NAME':<20} COMMAND")
    print("-" * 70)
    
    for proc in procs:
        cmdline = proc["cmdline"]
        if len(cmdline) > 50:
            cmdline = cmdline[:47] + "..."
        print(f"{proc['pid']:<8} {proc['uid']:<8} {proc['name']:<20} {cmdline}")
    
    print(f"\nTotal: {len(procs)} process(es)")


def print_fd_summary(pid):
    """Print a summary of file descriptor types for a process."""
    fds = inspect_pid_fds(pid)
    
    if not fds:
        print(f"PID {pid}: No file descriptors or process not accessible")
        return
    
    type_counts = defaultdict(int)
    for fd in fds:
        type_counts[fd["type"]] += 1
    
    name = get_process_name(pid)
    print(f"\nFile Descriptor Summary for {name} (PID {pid})")
    print("=" * 50)
    
    for fd_type, count in sorted(type_counts.items()):
        print(f"  {fd_type:<15} {count}")
    
    print(f"  {'TOTAL':<15} {len(fds)}")


def main():
    parser = argparse.ArgumentParser(
        description="Inspect file descriptors of running processes on Linux.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -l                          List all processes
  %(prog)s -l -s nginx                 List processes matching 'nginx'
  %(prog)s -p 1234                     Show FDs for PID 1234
  %(prog)s -p 1234 -t socket           Show only socket FDs
  %(prog)s -p 1234 --summary           Show FD type summary
  %(prog)s -p 1234 -a                  Show full paths (no truncation)
"""
    )
    
    parser.add_argument(
        "-l", "--list",
        action="store_true",
        help="List all running processes"
    )
    
    parser.add_argument(
        "-p", "--pid",
        type=int,
        help="Inspect file descriptors for specific PID"
    )
    
    parser.add_argument(
        "-s", "--search",
        type=str,
        help="Search term to filter process names"
    )
    
    parser.add_argument(
        "-u", "--user",
        type=str,
        help="Filter by UID"
    )
    
    parser.add_argument(
        "-t", "--type",
        choices=["file", "socket", "pipe", "device", "anon_inode", "other"],
        help="Filter FDs by type"
    )
    
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Show summary of FD types instead of full list"
    )
    
    parser.add_argument(
        "-a", "--all",
        action="store_true",
        help="Show full paths without truncation"
    )
    
    args = parser.parse_args()
    
    if args.list:
        print_process_list(args.search, args.user)
        return 0
    
    if args.pid:
        pid = args.pid
        
        try:
            name = get_process_name(pid)
            cmdline = get_process_cmdline(pid)
            uid = get_process_user(pid)
            
            print(f"\nProcess: {name}")
            print(f"PID: {pid}")
            print(f"UID: {uid}")
            print(f"Command: {cmdline}")
        except (PermissionError, ProcessLookupError):
            print(f"Error: Cannot access process {pid}")
            return 1
        
        if args.summary:
            print_fd_summary(pid)
        else:
            fds = inspect_pid_fds(pid, filter_type=args.type)
            print(f"\n{format_fd_table(fds, show_all=args.all)}")
            print(f"\nTotal FDs: {len(fds)}")
        
        return 0
    
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
