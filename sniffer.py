from scapy.all import sniff, IP, ICMP, TCP, UDP, Ether, Raw, Padding, GRE # explicit imports
import time
import random


def initial_state():
    return{
        "clean": True, # common transport status 
        "packets_sniffed": 0, # total volume sniffed tracker
        "transport_field": '', 
        "checker": ['TCP', 'UDP', 'ICMP'], # common transports 
        "input_tracker": 1, # current packet / table keys
        "raw_inputs": {}, # intial packet input
        "filtered_inputs": {}, # Dict for formatted outputs / cleaning variables
        "consecutive_hits": 0, 
        "DDoS_flag": False,
        "last_src_ip": None, 
        #Port holders for respective checks (ip_ports is horizontal)
        "ip_ports": {}, #Used for port scan checks
        "vertical_ip_ports": {},
        "seq_ip_ports": {},
        #Scanner flags
        "horizontal_port_scanner": False,
        "vertical_port_scanner": False,
        "sequential_port_scanner": False,
        "port_scanner": False,
        "packet_amount": 50,
        "capture_summary": "",
        "suspect_src_ips_DDoS": set(),
        "suspect_src_ips_port": set(), 
        "current_src_ip": None,
        #Severity is used for coloring in the gui in output.py
        "severity": 0,
        "port_scan_type": {},
        # True is real packets, False are fake packets
        "pkt_choice": False
    }

# Gets the port numbers and transport field from the current packet
def transport_check(state, pkt):

        if TCP in pkt:
            transport_field = "TCP"
            flex_src_port = pkt[TCP].sport
            flex_dst_port = pkt[TCP].dport
        elif UDP in pkt:
            transport_field = "UDP"
            flex_src_port = pkt[UDP].sport
            flex_dst_port = pkt[UDP].dport
        elif ICMP in pkt:
            transport_field = "ICMP"
            flex_src_port = None
            flex_dst_port = None
        else:
            transport_field = "unknown"
            flex_src_port = None
            flex_dst_port = None
            state["severity"]+=1
        return transport_field, flex_src_port, flex_dst_port

#Checks if the current packets transport is common
def clean_transport_check(transport, checker):
    if transport in checker:
         return True
    else:
         return False

 # Horizontal port scanner
def update_port_scan_check(state, src_ip, dst_ip, dst_port):
    #Main process of checking whether more/equal to 5 ports have been scanned from same source ip to multiple dst ips with same number i.e. 55 scanned 5 times acrsos 5 separate dst ips
    if dst_port is None:
        return False
    if src_ip not in state["ip_ports"]:
        state["ip_ports"][src_ip] = {dst_port: {dst_ip}}
        #Main logic loop here considers total locations from a src_ip, if it looks across many sources quickly it gets flagged
        #Note while this structure looks messy using {src_ip: {dst_port: set(dst_ips)}} Makes the tracking much easier
    if src_ip in state["ip_ports"]:
        if dst_port in state["ip_ports"][src_ip] and dst_ip in state["ip_ports"][src_ip][dst_port]:
            return False
        if dst_port in state["ip_ports"][src_ip] and dst_ip not in state["ip_ports"][src_ip][dst_port]:
            state["ip_ports"][src_ip][dst_port].add(dst_ip)
        if dst_port not in state["ip_ports"][src_ip]:
            state["ip_ports"][src_ip][dst_port] = {dst_ip}
            state["ip_ports"][src_ip][dst_port].add(dst_ip)
        #Main trigger for port update
        if len(state["ip_ports"][src_ip][dst_port]) >= 5:
            state["suspect_src_ips_port"].add(src_ip)
            state["severity"] += 1
            return True
    return False
#Verticcal port scanner
# Checks whether the dst_ip is checking the same ip for multiple ports and flags if 5 ports are checked from the same dst
def update_port_scan_check_vertical(state, src_ip, dst_ip, dst_port):
    if dst_port is None:
        return False
    # Structure looks like {src_ip: {dst_ip: {dst_port}}} 
    if src_ip not in state["vertical_ip_ports"]:
        state["vertical_ip_ports"][src_ip] = {dst_ip: {dst_port}}
    if src_ip in state["vertical_ip_ports"]:
        if dst_ip in state["vertical_ip_ports"][src_ip] and dst_port in state["vertical_ip_ports"][src_ip][dst_ip]:
            return False
        if dst_ip not in state["vertical_ip_ports"][src_ip]:
            state["vertical_ip_ports"][src_ip][dst_ip] = {dst_port}
        if dst_port not in state["vertical_ip_ports"][src_ip][dst_ip]:
            state["vertical_ip_ports"][src_ip][dst_ip].add(dst_port)
        #This is the trigger for the scanner, severity updates, and set gets updated for gui prints
        if len(state["vertical_ip_ports"][src_ip][dst_ip]) >= 5:
            state["suspect_src_ips_port"].add(src_ip)
            state["severity"] += 1
            return True
    return False
#sequential port scanner 
# 
def update_port_scan_check_sequential(state, src_ip, dst_ip, dst_port):
    if dst_port is None:
        return False
    if src_ip not in state["seq_ip_ports"]:
        state["seq_ip_ports"][src_ip] = {dst_ip: {dst_port}}
    if src_ip in state["seq_ip_ports"]:
        if dst_ip in state["seq_ip_ports"][src_ip] and dst_port in state["seq_ip_ports"][src_ip][dst_ip]:
            return False
        if dst_ip not in state["seq_ip_ports"][src_ip]:
            state["seq_ip_ports"][src_ip][dst_ip] = {dst_port}
        if dst_port not in state["seq_ip_ports"][src_ip][dst_ip]:
            state["seq_ip_ports"][src_ip][dst_ip].add(dst_port)
        #Main checker for sequential pattern, sorted works because if ports 10 and 1000 are scanned in same dst_port the offset would never be <= 3 anyways
        if len(state["seq_ip_ports"][src_ip][dst_ip]) >= 4:
            port_list = list(state["seq_ip_ports"][src_ip][dst_ip])
            port_list = sorted(port_list)
            comparison = 0
            #Compare to end of list if change is <= 3
            for index, value in enumerate(port_list[:-1]):  
                    first_number = value
                    second_number = port_list[index + 1]
                    change = abs(first_number - second_number)
                    if change == 1 or change == 2 or change == 3:
                        comparison += 1
                    else: 
                        return False
            if src_ip not in state["suspect_src_ips_port"]:
                state["suspect_src_ips_port"].add(src_ip)
                state["severity"] += 1
            return True
        return False

# NEXT STEP IS RESTRUCTURING THIS to an acutal ddoschecker
def update_DDoS_check(state, current_src_ip, dst_ip):




    if current_src_ip == state["last_src_ip"]: 
        state["consecutive_hits"] += 1
    else:
        state["consecutive_hits"] = 1
    if state["consecutive_hits"] >= 3:
        state["DDoS_flag"] = True
        state["severity"] += 1
    else:
        state["DDoS_flag"] = False
    state["last_src_ip"] = current_src_ip
    return state["DDoS_flag"]

def fake_packet_generation(state):
    i = state["input_tracker"]
    if i <= 51:
        # Variable initialization (randoms are used for fake packet filling)
        random_one = random.randint(0, 9)
        random_two = random.randint(10, 40)
        random_three = random.randint(100, 999) 

        if random_two % 3 == 0:
            fake_transport = TCP()
        elif random_two % 3 == 1:
            fake_transport = UDP()
        else: fake_transport = ICMP()

        if random_three % 3 == 0:
            fake_last = Raw()
        if random_three % 3 == 1:
            fake_last = Padding()
        else: fake_last = Raw()

        if i <= 5:
            pkt = Ether() / IP(src = f"10.10.0.10", dst =f"20.20.0.{random_two}") / TCP(sport = random_two, dport = 99) / fake_last
        elif i <= 10:
            pkt = Ether() / IP(src = f"10.10.0.20", dst = f"20.20.0.88") / TCP(sport = random_two, dport = random_two) / fake_last    
        elif i == 15:
            pkt = Ether() / IP(src = f"10.10.0.30", dst = f"20.20.0.88") / TCP(sport = random_two, dport = 5) / fake_last
        elif i == 16: 
            pkt = Ether() / IP(src = f"10.10.0.30", dst = f"20.20.0.88") / TCP(sport = random_two, dport = 8) / fake_last
        elif i == 17:
            pkt = Ether() / IP(src = f"10.10.0.30", dst = f"20.20.0.88") / TCP(sport = random_two, dport = 10) / fake_last
        elif i == 18:
            pkt = Ether() / IP(src = f"10.10.0.30", dst = f"20.20.0.88") / TCP(sport = random_two, dport = 9) / fake_last
        elif i == 19:
            pkt = Ether() / IP(src = f"10.10.0.30", dst = f"20.20.0.88") / TCP(sport = random_two, dport = 7)/ fake_last
        elif i <= 20:
            pkt = Ether() / IP(src = f"10.10.0.66", dst = f"20.20.0.88") / GRE() / fake_last
        elif i <= 25:
            pkt = Ether() / IP(src = f"10.10.0.99", dst = f"20.20.0.{random_one}") / UDP(sport=67890, dport=99) / fake_last
        elif i <= 30:
            pkt = Ether() / IP(src = f"10.10.0.{random_one}", dst = f"20.20.0.99") / fake_transport / fake_last
        elif i <= 35:
            pkt = Ether() / IP(src = f"10.10.0.99", dst = f"20.20.0.{random_one}") / UDP(sport=12345, dport=random_two) / fake_last
        elif i <= 40:
            pkt = Ether() / IP(src = f"10.10.0.77", dst = f"20.20.0.77") / fake_transport / fake_last
        elif i <= 48:
            pkt = Ether() / IP(src = f"10.10.0.{random_one}", dst = f"20.20.0.{random_one}") / GRE() / fake_last
        elif i == 49:
             pkt = Ether() / IP(src = f"10.10.0.99", dst = f"20.20.0.{random_one}") / GRE() / fake_last
        elif i == 50:
            pkt = Ether() / IP(src = f"10.10.0.99", dst = f"20.20.0.77") / GRE() / fake_last

    return pkt



def process_packet(state, pkt): 
    #Reset severity and grab the packets information
    state["severity"] = 0
    state["capture_summary"] = pkt.summary()
    dst_ip = pkt[IP].dst if IP in pkt else None

    #Uses transport_check function for finding flex_src and flex_dst for raw_inputs dict while gatherhing transport_field for comparison
    transport_field, flex_src_port, flex_dst_port = transport_check(state, pkt)
    state["clean"] = clean_transport_check(transport_field, state["checker"])


    # Checks the last packet layer and whether its padding or raw for dict
    last_layer = pkt.lastlayer()
    padding_or_raw = last_layer if last_layer.name in ("Padding", "Raw") else None

    # Add fields of the captured packet to dictionary using variables grabbed in last few prior lines (flex_src and flex_dst are both given in the raw pkt check)
    state["raw_inputs"][state["input_tracker"]] = {
            "Padding": padding_or_raw, 
            "Transport": transport_field,
            "Internet-Protocol": {"src": pkt[IP].src if IP in pkt else None, "dst": pkt[IP].dst if IP in pkt else None},
            "Port-Numbers": {"src_port": flex_src_port, "dst_port": flex_dst_port}
        }
    
    # Gets the current transport field 
    state["transport_field"] = state["raw_inputs"][state["input_tracker"]]["Transport"] 

    #DDoS check and current ip tracking
    current_src_ip = pkt[IP].src if IP in pkt else ''
    state["current_src_ip"] = current_src_ip
    update_DDoS_check(state, current_src_ip, dst_ip)

    #Updates suspect ips if DDoS is detected
    if state["DDoS_flag"] is True:
        state["suspect_src_ips_DDoS"].add(current_src_ip)

    #port_scanner checks 
    state["horizontal_port_scan"] = update_port_scan_check(state, current_src_ip, dst_ip, flex_dst_port)
    state["vertical_port_scan"] = update_port_scan_check_vertical(state, current_src_ip, dst_ip, flex_dst_port)
    state["sequential_port_scan"] = update_port_scan_check_sequential(state, current_src_ip, dst_ip, flex_dst_port)
    if state["horizontal_port_scan"] is True or state["vertical_port_scan"] is True or state["sequential_port_scan"] is True:
        state["port_scanner"] = True
    else:
        state["port_scanner"] = False
    
    

    # Add to the filtered_inputs dict with key information like clean status, type of input, and the DDOS flag ||| Going to use for clean output tracking
    state["filtered_inputs"][state["input_tracker"]] = {
        "clean": state["clean"], 
        "type": state["transport_field"], #This is the Transport protocol  
        "DDoS": state["DDoS_flag"]

        }
    
        
    #Advancing current packet (for dictionary entries) and total packets sniffed
    state["input_tracker"] += 1
    state["packets_sniffed"] += 1
    time.sleep(0.5)
    return state


def receive(state):
    #state should be shared by who is calling it rather than initialized
    while True:
            
            print("-" * 120)
            # packet capture system
            if state["pkt_choice"]: 
                capture = sniff(count=1)
                pkt = capture[0]
                capture.summary()
            else:
                pkt = fake_packet_generation(state)
                print(pkt.summary())
            
            #Sends important information to process_packet function since I want to test 
            process_packet(state, pkt)

            current_pkt_index = state["input_tracker"] - 1
            print("Number: ", current_pkt_index)
            print("Transport: ", state["raw_inputs"].get(current_pkt_index, {}).get("Transport"))
            print("Padding: ", state["raw_inputs"].get(current_pkt_index, {}).get("Padding"))
            print("Clean: ", state["filtered_inputs"].get(current_pkt_index, {}).get("clean"))
            print("DDoS: ", state["filtered_inputs"].get(current_pkt_index, {}).get("DDoS"))
            print("Horizontal Scanner: ", state["horizontal_port_scan"])
            print("Vertical Scanner: ", state["vertical_port_scan"])
            print("Sequential Scanner: ", state["sequential_port_scan"])
            print("Port Scanner: ", state["port_scanner"])
            print("Suspect DDoS IPs:", state["suspect_src_ips_DDoS"])
            print("Suspect Port IPs: ", state["suspect_src_ips_port"])
            print("Severity: ", state["severity"])

            if state["packets_sniffed"] >= state["packet_amount"]:
                break
            