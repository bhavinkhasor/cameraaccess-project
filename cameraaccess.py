import socket
import ipaddress
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==============================
# CONFIG
# ==============================

TIMEOUT = 0.5
MAX_WORKERS = 50


# ==============================
# GET LAPTOP IP
# ==============================

def get_local_ip():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip
    except Exception:
        return None


# ==============================
# GET SUBNET
# ==============================

def get_network(local_ip):
    """
    Assumes a typical /24 home Wi-Fi network.
    Example:
    192.168.1.25 -> 192.168.1.0/24
    """

    if not local_ip:
        return None

    parts = local_ip.split(".")

    if len(parts) != 4:
        return None

    network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    return ipaddress.ip_network(network, strict=False)


# ==============================
# PING DEVICE
# ==============================

def ping_device(ip):

    system = platform.system().lower()

    if system == "windows":
        command = [
            "ping",
            "-n",
            "1",
            "-w",
            "500",
            str(ip)
        ]
    else:
        command = [
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            str(ip)
        ]

    try:

        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return result.returncode == 0

    except Exception:
        return False


# ==============================
# GET HOSTNAME
# ==============================

def get_hostname(ip):

    try:
        hostname = socket.gethostbyaddr(str(ip))[0]
        return hostname

    except Exception:
        return "Unknown"


# ==============================
# PORT SCANNER
# ==============================

COMMON_CAMERA_PORTS = [
    80,      # HTTP
    443,     # HTTPS
    554,     # RTSP
    8000,
    8080,
    8081,
    8899,
    5000
]


def scan_ports(ip):

    open_ports = []

    for port in COMMON_CAMERA_PORTS:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(TIMEOUT)

        try:

            result = sock.connect_ex(
                (str(ip), port)
            )

            if result == 0:
                open_ports.append(port)

        except Exception:
            pass

        finally:
            sock.close()

    return open_ports


# ==============================
# DEVICE ANALYSIS
# ==============================

def analyze_device(ip):

    if not ping_device(ip):
        return None

    hostname = get_hostname(ip)

    open_ports = scan_ports(ip)

    camera_score = 0

    # RTSP
    if 554 in open_ports:
        camera_score += 5

    # Common HTTP camera ports
    if 80 in open_ports:
        camera_score += 1

    if 8080 in open_ports:
        camera_score += 1

    if 8000 in open_ports:
        camera_score += 1

    if 8899 in open_ports:
        camera_score += 2

    if camera_score >= 3:

        device_type = "LIKELY CAMERA"

    elif camera_score > 0:

        device_type = "POSSIBLE CAMERA"

    else:

        device_type = "OTHER DEVICE"

    return {
        "ip": str(ip),
        "hostname": hostname,
        "ports": open_ports,
        "type": device_type
    }


# ==============================
# MAIN SCANNER
# ==============================

def main():

    print("\n==========================================")
    print("      NETWORK CAMERA DISCOVERY SYSTEM")
    print("==========================================\n")

    local_ip = get_local_ip()

    if not local_ip:

        print("❌ Could not detect laptop IP.")

        return

    print(f"💻 Laptop IP : {local_ip}")

    network = get_network(local_ip)

    if not network:

        print("❌ Could not determine network.")

        return

    print(f"🌐 Network   : {network}")

    print("\n🔍 Scanning network...")
    print("Please wait...\n")

    devices = []

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {
            executor.submit(
                analyze_device,
                ip
            ): ip

            for ip in network.hosts()
        }

        for future in as_completed(futures):

            try:

                result = future.result()

                if result:
                    devices.append(result)

            except Exception:
                pass

    devices.sort(
        key=lambda x: ipaddress.ip_address(x["ip"])
    )

    # ==============================
    # RESULTS
    # ==============================

    print("\n==========================================")
    print("              SCAN RESULTS")
    print("==========================================\n")

    if not devices:

        print("❌ No active devices found.")

        return

    print(
        f"{'IP ADDRESS':<18}"
        f"{'HOSTNAME':<25}"
        f"{'PORTS':<25}"
        f"{'TYPE'}"
    )

    print("-" * 90)

    cameras = []

    for device in devices:

        ports = ", ".join(
            str(port)
            for port in device["ports"]
        )

        print(
            f"{device['ip']:<18}"
            f"{device['hostname'][:24]:<25}"
            f"{ports:<25}"
            f"{device['type']}"
        )

        if "CAMERA" in device["type"]:

            cameras.append(device)

    # ==============================
    # CAMERA RESULTS
    # ==============================

    print("\n==========================================")
    print("             CAMERA RESULTS")
    print("==========================================\n")

    if cameras:

        print(
            f"🎥 Cameras detected: {len(cameras)}\n"
        )

        for camera in cameras:

            print(
                f"📷 Camera IP : {camera['ip']}"
            )

            print(
                f"   Hostname  : {camera['hostname']}"
            )

            print(
                f"   Ports     : {camera['ports']}"
            )

            print()

    else:

        print("⚠️ No obvious IP camera detected.")

        print(
            "\nThis does NOT necessarily mean your Mi 360"
            " camera is offline."
        )

        print(
            "Some cameras do not expose RTSP/HTTP ports"
            " to the local network."
        )

    print("\n==========================================")
    print("                 DONE")
    print("==========================================\n")


if __name__ == "__main__":
    main()