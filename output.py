import tkinter as tk

def print_packet_info(state, box):
    
    #get the current packet index(cpi) for recalling
    cpi = state['input_tracker'] - 1

    tag = "normal"
    danger = ""
    severity = state["severity"]
    if severity == 0:
        tag = "normal"
        danger = "None"
    elif severity == 1:
        tag = "low"
        danger = "Low"
    elif severity == 2:
        tag = "medium"
        danger = "Medium"
    else: 
        tag = "high"
        danger = "High"
    box.insert(tk.END, f"Severity: ")
    box.insert(tk.END, f"{danger}\n", tag)
    

    return (
        f"{state['capture_summary']}\n"
        f" Number of Packets: {cpi}\n"
        f" Transport: {state['raw_inputs'].get(cpi, {}).get('Transport')}\n"
        

        "-----------------------------------------------------------------------\n"

           
        )
#returns the DDoS_ip dict set from state
def print_suspect_ips_DDoS(state):
    ips = state.get('suspect_src_ips_DDoS', set())
    return f"{", ".join(ips)}\n"

#returns the port_scanner dict set from state
def print_suspect_ips_port(state):
    ips = state.get('suspect_src_ips_port', set())
    return f"{", ".join(ips)}\n"

# Color prints live tracking, UNCERTAIN IF CAN BE MODIFIED FOR EFFICIENCY RATHER THAN MULTi LOOP
def live_tracking_print(state, box): 

    #Clear the top right box
    box.delete("1.0", tk.END)

    #Begin adding live tracking stats
    box.insert(tk.END, f"Transport: {state.get('transport_field')}\n\n")
    
    #depending on true/false return color of tag changes
    if state.get('clean'):
        tag = "good"
    else: tag = "bad"
    box.insert(tk.END, f"Clean = {state.get('clean')}\n\n", tag)

    if state.get('DDoS_flag'):
        tag = "bad"
    else: tag = "good"
    box.insert(tk.END, f"DDoS = {state.get('DDoS_flag')}\n\n", tag)

    if state.get('port_scanner'):
        tag = "bad"
    else: tag = "good"
    box.insert(tk.END, f"Port Scanner = {state.get('port_scanner')}\n\n", tag)

def start_gui(state):

    root = tk.Tk()  
    root.geometry("1200x600")


    #Middle black line
    divider = tk.Frame(root, width=2, bg="black")
    divider.place(relx=0.55, rely=0, relheight=1.0)


    # Creates a frame for the left side of the screen
    left_frame = tk.Frame(root, width=5, height=5)
    left_frame.pack(side="left", fill="both", expand=True)

    
## Left side of the screen creates labels and boxes using left_frame position

    # Label for the DDoS IPs
    suspect_label_DDoS = tk.Label(left_frame, text="Suspect DDoS IPs:")
    suspect_label_DDoS.pack(anchor="nw")
    #Print for the DDoS IPS
    suspect_box_DDoS = tk.Text(left_frame, height = 5, width = 80)
    suspect_box_DDoS.pack(anchor="nw")


    # Label for the port IPs
    suspect_label_port = tk.Label(left_frame, text="Suspect Port IPs: ")
    suspect_label_port.pack(anchor="nw")
    #Print for the port IPS
    suspect_box_port = tk.Text(left_frame, height = 5, width = 80)
    suspect_box_port.pack(anchor="nw")


    # For current packet printing (raw prints of the packets)
    packet_log_label = tk.Label(left_frame, text="Packet Log: ")
    packet_log_label.pack(anchor="sw")

    packet_log = tk.Text(left_frame, height=45, width=80)
    packet_log.pack(anchor="sw")
    packet_log.tag_configure("low", foreground="blue")
    packet_log.tag_configure("medium", foreground="orange")
    packet_log.tag_configure("high", foreground="red")
    packet_log.tag_configure("normal", foreground="black")


    #Creation of frame on right side of screen (Won't be used I think)
    right_frame = tk.Frame(root, width=5, height=5)
    right_frame.pack(side="right", fill="both", expand=True)

    live_tracking_label = tk.Label(right_frame, text="Live Tracking: ", padx=250)
    live_tracking_label.pack(anchor="ne")

    live_tracking_box = tk.Text(right_frame, height=10, width=40)
    live_tracking_box.pack(anchor="ne")

    live_tracking_box.tag_configure("good", foreground="green")
    live_tracking_box.tag_configure("bad", foreground="red")

    # Variable tracking last_packet_index for dictionary recall | amount for suspect ip tracking
    last_packet_index = -1
    DDoS_amount = 0
    port_amount = 0
    DDoS_print_tracker = 0
    port_print_tracker = 0

    # main gui update function
    def update_gui():

        #nonlocals used as update gui loops itself based on root.after(1000, update_gui) 1000 being the loop time. 
        nonlocal last_packet_index
        nonlocal DDoS_amount 
        nonlocal port_amount
        nonlocal DDoS_print_tracker
        nonlocal port_print_tracker
        current_src_ip = state.get("current_src_ip", "")
        current_packets = state.get("packets_sniffed", 0)
       

    ## This loop is using the last_packet_index to ensure that another packet isn't needed to be printed
    ## The update_gui is polling at 1000, so the same packet would print repeatedly. This loop checks each packet state once
        if current_packets - 1 > last_packet_index:
            last_packet_index = current_packets - 1

            #Printing the current packet RAW info based on packet_log positioning (Bottom left)
            log_text = print_packet_info(state, packet_log)
            packet_log.insert(tk.END, log_text)
            packet_log.see(tk.END)

            # FIXED IT PRINTS COLOR NOW !!! YAYAYYYY BUDDAY
            live_tracking_print(state, live_tracking_box)
            
            # The same ip will not be added twice due to logic in sniffer.py, however it would print repeatedly without this function
            # Function ensures each ip prints the dict set once
            if DDoS_amount != len(state["suspect_src_ips_DDoS"]) and DDoS_print_tracker < len(state["suspect_src_ips_DDoS"]):
                suspect_text_DDoS = print_suspect_ips_DDoS(state)
                suspect_box_DDoS.insert(tk.END, suspect_text_DDoS)
                suspect_box_DDoS.see(tk.END)
                DDoS_amount += 1
                DDoS_print_tracker += 1
            if port_amount != len(state["suspect_src_ips_port"]) and port_print_tracker < len(state["suspect_src_ips_port"]):
                suspect_text_port = print_suspect_ips_port(state)
                suspect_box_port.insert(tk.END, suspect_text_port)
                suspect_box_port.see(tk.END)
                port_amount += 1
                port_print_tracker += 1
                


        # always schedule next update so GUI continues polling shared state
        root.after(400, update_gui)

    # Start the update loop and run the GUI
    update_gui()
    root.mainloop()


