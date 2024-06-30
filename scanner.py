## A tool that realizes different enumerations in your machine; processes, connections, and system information and users.
## This version support Windows and Unix operating systems.

import sys
import psutil
import socket
import platform
import argparse
from termcolor import colored


__version__ = "2.0.0"


# Arguments / Flags
parser = argparse.ArgumentParser(add_help=False)

parser.add_argument("-m", "--mode")
parser.add_argument("-s", "--save", default="report")
parser.add_argument("-h", "--help", action="store_true")
argument = parser.parse_args()

# Help message
def help_message() -> None:
    print(colored("HELP MESSAGE", "yellow") + 
    f'''\r\nScanner script | Version: {__version__}
    \rA tool that realizes different enumerations in your machine; processes, connections, and system information and users. This tool runs in Windows and Linux/UNIX devices.
    \r\nOPTIONS:
    \r   -h, --help               Show this message and exit.
    \r   -m MODE, --mode MODE     Chose a scan mode, required argument: Mode-number.
    \r   -s SAVE, --save SAVE     Save the scan in a report, required argument: File-name.
    \r\nSCAN MODES:
    \r[0] TCP Processes
    \r[1] UDP Processes
    \r[2] System scan
    \r\nDEFAULT FILE-NAME:
    \r[+] report.txt\n''')
    return None


# Main function
def main() -> None:
    if argument.help:
        help_message()
        sys.exit(0)

    if not verify_mode():
        print("[!] Invalid option, please select a valid mode\n")
        sys.exit(1)

    match argument.mode:
        case 0:
            TCP_connections()
        case 1:
            UDP_connections()
        case 2:
            system_scan()
    return None

# Mode-number Error management
def verify_mode() -> bool:
    try:
        argument.mode = int(argument.mode)
    except (ValueError, TypeError):
        return False
    if argument.mode < 0 or argument.mode > 2:
        return False
    else:
        return True


# Option functions
## TCP Scan - Option 0
def TCP_connections() -> None:
    print(colored("Executing TCP process scan", "yellow"))
    connections = psutil.net_connections(kind="tcp")
    n = 1
    for conn in connections:
        pid = conn.pid
        process = psutil.Process(pid)
        ## Remote an local IP address
        ## conn.raddr and conn.laddr are tuples (ip, port) ->  [index:(0, 1)]
        laddr = f"{conn.laddr[0]}:{conn.laddr[1]}" if conn.laddr else "N/A"
        raddr = f"{conn.raddr[0]}:{conn.raddr[1]}" if conn.raddr else "N/A"

        ## Hostname
        if laddr == "N/A":
            lhostname = "Unknown"
        else:
            try:
                lhostname, _, _ = socket.gethostbyaddr(conn.laddr[0])
            except (socket.herror, IndexError):
                lhostname = "Unknown"
        if raddr == "N/A":
            rhostname = "Unknown"
        else:
            try:
                rhostname, _, _ = socket.gethostbyaddr(conn.raddr[0])
            except (socket.herror, IndexError):
                rhostname = "Unknown"

        print("Connection (" + colored(f"{n}", "light_magenta") + "):")
        print(f"Process: {process.name()}\nPID: {pid}")
        print(f"LADDR: {laddr}\nLHOSTNAME: {lhostname}")
        print(colored(f"RADDR: {raddr}\nRHOSTNAME: {rhostname}", "cyan"))
        
        ## Checking the status
        if process.status() == "running":
            print("Status: " + colored(f"{process.status()}\n\n", "light_green"))
        else:
            print("Status: " + colored(f"{process.status()}\n\n", "red"))
        n += 1
    return None

## UDP Scan - Option 1
def UDP_connections() -> None:
    print(colored("Executing UDP process scan", "yellow"))
    connections = psutil.net_connections(kind="udp")
    n = 1
    for conn in connections:
        pid = conn.pid
        process = psutil.Process(pid)
        ## Remote an local IP address
        ## conn.raddr and conn.laddr are tuples (ip, port) ->  [index:(0, 1)]
        laddr = f"{conn.laddr[0]}:{conn.laddr[1]}" if conn.laddr else "N/A"
        raddr = f"{conn.raddr[0]}:{conn.raddr[1]}" if conn.raddr else "N/A"

        ## Hostname
        if laddr == "N/A":
            lhostname = "Unknown"
        else:
            try:
                lhostname, _, _ = socket.gethostbyaddr(conn.laddr[0])
            except (socket.herror, IndexError):
                lhostname = "Unknown"
        if raddr == "N/A":
            rhostname = "Unknown"
        else:
            try:
                rhostname, _, _ = socket.gethostbyaddr(conn.raddr[0])
            except (socket.herror, IndexError):
                rhostname = "Unknown"

        print("Connection (" + colored(f"{n}", "light_magenta") + "):")
        print(f"Process: {process.name()}\nPID: {pid}")
        print(f"LADDR: {laddr}\nLHOSTNAME: {lhostname}")
        print(colored(f"RADDR: {raddr}\nRHOSTNAME: {rhostname}", "cyan"))
        
        ## Checking the status
        if process.status() == "running":
            print("Status: " + colored(f"{process.status()}\n\n", "light_green"))
        else:
            print("Status: " + colored(f"{process.status()}\n\n", "red"))
        n += 1
    return None

## General System Scan - Option 2
def system_scan() -> None:
    users = psutil.users()

    print(colored("System information", "yellow"))
    print(f"OS: {platform.system()}\nBits: {platform.machine()}\n")
    
    print(colored("CPU information", "yellow"))
    print(f"CPU: {platform.processor()}\nPhysical Cores: {psutil.cpu_count(logical=False)}\nLogical Cores: {psutil.cpu_count(logical=True)}\nFrecuency: {psutil.cpu_freq().current} Hz\n")

    print(colored("Listing all conected users", "yellow"))
    n = 1
    for user in users:
        print("User (" + colored(f"{n}", "light_magenta") + "):")
        print(f"Name: {user.name}\nHostname: {user.host}\nTerminal: {user.terminal}\n")
    return None


# Initialize script
if __name__ == "__main__":
    main()
