import threading
from sniffer import initial_state, receive
from output import start_gui

#This allows sharing of state rather than initializing in each function
state = initial_state()

# Run sniffer in background, thread allows both output and sniffer to run at the same time
sniffer_thread = threading.Thread(target=receive, args=(state,))
sniffer_thread.daemon = True
sniffer_thread.start()

# Run GUI (main thread)
start_gui(state)
