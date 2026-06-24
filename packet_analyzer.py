from scapy.all import sniff, IP, TCP, UDP, ICMP


# Counters
packet_count = 0
tcp_count = 0
udp_count = 0
icmp_count = 0


# Store packets
captured_packets = []


def analyze_packet(packet):

    global packet_count
    global tcp_count
    global udp_count
    global icmp_count


    # Store every packet
    captured_packets.append(packet)

    packet_count += 1


    print("\n" + "─" * 50)
    print(f"PACKET #{packet_count}")
    print("─" * 50)


    if IP in packet:

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst


        print(f"Source IP        : {src_ip}")
        print(f"Destination IP   : {dst_ip}")


        if TCP in packet:

            tcp_count += 1

            print("Protocol         : TCP")
            print(f"Source Port      : {packet[TCP].sport}")
            print(f"Destination Port : {packet[TCP].dport}")


        elif UDP in packet:

            udp_count += 1

            print("Protocol         : UDP")
            print(f"Source Port      : {packet[UDP].sport}")
            print(f"Destination Port : {packet[UDP].dport}")


        elif ICMP in packet:

            icmp_count += 1

            print("Protocol         : ICMP")


        else:

            print("Protocol         : OTHER")


        print(f"Packet Length    : {len(packet)} bytes")



def print_summary(requested_packets):

    print("\n")
    print("═" * 50)
    print("TRAFFIC SUMMARY")
    print("═" * 50)


    print(f"Requested Packets : {requested_packets}")
    print(f"Captured Packets  : {packet_count}")

    print()

    print(f"TCP Packets       : {tcp_count}")
    print(f"UDP Packets       : {udp_count}")
    print(f"ICMP Packets      : {icmp_count}")



def view_packets(choice):

    print("\n")
    print("═" * 50)
    print("FILTERED PACKETS")
    print("═" * 50)


    display_count = 0


    for packet in captured_packets:


        protocol = "OTHER"


        if TCP in packet:
            protocol = "TCP"

        elif UDP in packet:
            protocol = "UDP"

        elif ICMP in packet:
            protocol = "ICMP"



        # Filtering
        if choice != "ALL" and protocol != choice:
            continue



        display_count += 1


        print("\n" + "─" * 50)
        print(f"PACKET #{display_count}")
        print("─" * 50)


        if IP in packet:

            print(f"Source IP        : {packet[IP].src}")
            print(f"Destination IP   : {packet[IP].dst}")
            print(f"Protocol         : {protocol}")
            print(f"Packet Length    : {len(packet)} bytes")



    if display_count == 0:

        print("\nNo packets found for this selection.")





print("╔════════════════════════════════════╗")
print("║      NETWORK PACKET ANALYZER       ║")
print("╚════════════════════════════════════╝")



# User input

capture_time = int(input("\nEnter capture time (seconds): "))

packet_limit = int(input("Enter packets to capture(max): "))



print("\nStarting packet capture...")
print("Generate some traffic (open browser, ping websites, etc.)\n")



try:


    sniff(
        prn=analyze_packet,
        timeout=capture_time,
        count=packet_limit,
        store=False
    )


except PermissionError:


    print("\nPermission denied.")
    print("Run VS Code/Python as Administrator.")



except KeyboardInterrupt:


    print("\nCapture stopped by user.")




# Summary

print_summary(packet_limit)



# Packet selection

print("\nSelect packets to display:")
print("1. TCP")
print("2. UDP")
print("3. ICMP")
print("4. All")


choice = input("\nEnter your choice: ")



if choice == "1":

    selected = "TCP"


elif choice == "2":

    selected = "UDP"


elif choice == "3":

    selected = "ICMP"


else:

    selected = "ALL"



view_packets(selected)