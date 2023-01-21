from scapy.all import ARP, Ether, srp
import socket, struct

def get_default_gateway_linux():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                # If not default route or not RTF_GATEWAY, skip it
                continue

            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

# Get the default gateway IP address
gateway = get_default_gateway_linux()

# IP Address for the destination
target_ip = gateway + "/24"

# Create ARP packet
arp = ARP(pdst=target_ip)

# Create the Ether broadcast packet
# ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
ether = Ether(dst="ff:ff:ff:ff:ff:ff")

# Stack them
packet = ether/arp

# Send packet and get the result
result = srp(packet, timeout=3, verbose=0)[0]

# A list of clients, we will fill this in the upcoming loop
clients = []

# For each response, append IP and MAC address to `clients` list
for sent, received in result:
    clients.append({'ip': received.psrc, 'mac': received.hwsrc})

# Print clients
print("Available devices in the network:")
print("IP" + " "*18+"MAC")
for client in clients:
    print("{:16}    {}".format(client['ip'], client['mac']))
