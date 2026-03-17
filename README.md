# proc-fd-inspector

Inspect file descriptors of running processes on Linux.

## Why I Built This

Ever had a process holding onto a deleted file and eating up disk space? Or wondered why a service won't release a port? This tool lets you peek into what files, sockets, and pipes any process has open.

It reads directly from `/proc/<pid>/fd/` - no fancy dependencies, just pure Linux introspection.

## Quick Start

```bash
# List all processes
python proc_fd_inspector.py -l

# Search for a specific process
python proc_fd_inspector.py -l -s nginx

# Inspect FDs for a PID
python proc_fd_inspector.py -p 1234

# Show only sockets
python proc_fd_inspector.py -p 1234 -t socket

# Get a summary of FD types
python proc_fd_inspector.py -p 1234 --summary
```

## What It Shows

For each file descriptor you'll see:

| FD | Type | Target |
|----|------|--------|
| 0 | file | /dev/null |
| 1 | file | /var/log/app.log |
| 2 | file | /var/log/error.log |
| 3 | socket | socket:[12345] |
| 4 | pipe | pipe:[67890] |

Types:
- **file** - Regular files
- **socket** - Network sockets
- **pipe** - Pipes (including unnamed pipes)
- **device** - Device files in /dev/
- **anon_inode** - Anonymous inodes (eventfd, signalfd, etc.)
- **other** - Anything else

## Common Use Cases

### Find what's holding a file open

```bash
# List processes, find the one you care about
python proc_fd_inspector.py -l -s myapp

# Check its FDs
python proc_fd_inspector.py -p 4521
```

### Debug socket issues

```bash
# See all sockets a process has open
python proc_fd_inspector.py -p 4521 -t socket
```

### Check for deleted files still in use

```bash
# Full output shows "deleted" files
python proc_fd_inspector.py -p 4521 -a
```

## Requirements

- Python 3.6+
- Linux (uses /proc filesystem)
- Root access helps but not required (you'll only see processes you own)

## Notes

- Paths get truncated at 50 chars unless you use `-a`
- Some FDs might show `<unavailable>` if you lack permissions
- Process can exit between listing and inspection - that's normal

## License

MIT - do whatever you want with it.
