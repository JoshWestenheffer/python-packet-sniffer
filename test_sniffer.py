import unittest
from scapy.all import UDP, TCP, IP, ICMP

from sniffer import clean_transport_check, initial_state, update_port_scan_check, update_DDoS_check

class TestCleanTransportCheck(unittest.TestCase):

    def test_valid_transport(self):
        checker = ["TCP", "UDP", "ICMP"]
        self.assertTrue(clean_transport_check("TCP", checker))
    def test_invalid_transport(self):
        checker = ["TCP", "UDP", "ICMP"]
        self.assertFalse(clean_transport_check("ABC", checker))

class TestPortScanner(unittest.TestCase):

    #Port scan should be detected if 5 or more ports are scanned from same source ip
    def test_port_scan_detected(self):

        state = initial_state()
        src_ip = "11.22.33.44"

        ports = [10, 20, 30, 40, 50]
        detected = False

        for port in ports:
            detected = update_port_scan_check(state, src_ip, port)
        self.assertTrue(detected)

    #Port scanner should not be detected if port amount less than 5
    def test_port_scan_few_ports(self):

        state = initial_state()
        src_ip = "10.11.12.13"

        ports = [10, 20]
        detected = False
        
        for port in ports:
            detected = update_port_scan_check(state, src_ip, port)
        self.assertFalse(detected)

    #No dst_port edge case, this should return false as in main function empty port is set to None
    def test_port_scan_no_dst_port(self):
        state = initial_state()
        src_ip = "10"
        result = update_port_scan_check(state, src_ip, None)
        self.assertFalse(result)

    #No src_ip edge case, this should return false as in main funciton empty ip is set to None
    def test_port_scan_no_src_ip(self):
        state = initial_state()
        dst_port = "10"
        result = update_port_scan_check(state, None, dst_port)
        self.assertFalse(result)

class TestDDoSDetection(unittest.TestCase):

    #DDoS should be detected with 3 or more consecutive hits from same source ip
    def test_DDoS_detected(self):
        state  = initial_state()
        current_src_ip = "1"
     
        update_DDoS_check(state, current_src_ip)
        update_DDoS_check(state, current_src_ip)
        update_DDoS_check(state, current_src_ip)
        self.assertTrue(state["DDoS_flag"])
    
    #DDoS should not be detected without 3 consecutive hits from same source ip
    def test_DDoS_undetected(self):
        state = initial_state()
        current_src_ip = "2"
        update_DDoS_check(state, current_src_ip)
        self.assertFalse(state["DDoS_flag"])

if __name__ == "__main__":
    unittest.main() 