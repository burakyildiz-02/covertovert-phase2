from scapy.all import sniff
from scapy.layers.inet import IP, ICMP
import time

from CovertChannelBase import CovertChannelBase

class MyCovertChannel(CovertChannelBase):
    """
    A covert channel implementation using ICMP packet timing patterns.
    The channel uses burst patterns to encode binary data where:
    - A burst of size_1 packets represents binary 1
    - A burst of size_0 packets represents binary 0
    Bursts are separated by idle periods to ensure proper detection.
    """
    def __init__(self):
        """
        Initialize the covert channel by calling parent class constructor
        """
        super().__init__()

    def send(self, interface="eth0", burst_size_1=2, burst_size_0=1, idle_time=0.1, log_file_name="sending_log.log"):
        """
        Sends a covert message by encoding bits as ICMP packet burst patterns.
        
        Parameters:
        - interface: Network interface to send packets on (default: "eth0")
        - burst_size_1: Number of packets in a burst to represent binary 1 (default: 2)
        - burst_size_0: Number of packets in a burst to represent binary 0 (default: 1)
        - idle_time: Time to wait between bursts in seconds (default: 0.1)
        - log_file_name: File to log the sent message (default: "sending_log.log")
        
        Implementation:
        1. Generates random binary message and logs it
        2. For each bit:
           - Determines burst size (size_1 for 1, size_0 for 0)
           - Sends burst of ICMP packets
           - Waits idle_time between bursts
        3. Sends final packet to ensure last character processing
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        print(f"Sending binary message: {binary_message}")
        
        # Send each bit
        for bit in binary_message:
            burst_size = burst_size_1 if bit == '1' else burst_size_0
            print(f"Sending bit {bit} with burst size {burst_size}")
            
            # Send burst
            for _ in range(burst_size):
                packet = IP(dst="172.18.0.3")/ICMP()
                super().send(packet, interface=interface)
            
            # Wait between bursts
            time.sleep(idle_time)

        # Send a last packet to convert last bits to char
        packet = IP(dst="172.18.0.3")/ICMP()
        super().send(packet, interface=interface)

    def receive(self, interface="eth0", burst_size_1=2, burst_size_0=1, idle_threshold=0.05, log_file_name="received_log.log"):
        """
        Receives and decodes the covert message by analyzing ICMP packet timing patterns.
        
        Parameters:
        - interface: Network interface to listen on (default: "eth0")
        - burst_size_1: Expected burst size for binary 1 (default: 2)
        - burst_size_0: Expected burst size for binary 0 (default: 1)
        - idle_threshold: Time threshold to detect burst boundaries in seconds (default: 0.05)
        - log_file_name: File to log the received message (default: "received_log.log")
        
        Implementation:
        1. Initializes message collection variables
        2. For each packet:
           - Detects burst boundaries using timing
           - Counts packets within bursts
           - Converts burst sizes to binary (dividing by 2 to handle duplicates)
           - Assembles 8-bit groups into characters
        3. Stops when message ends with period
        4. Logs final message
        """
        message = ""
        current_bits = ""
        last_packet_time = None
        burst_count = 0

        def process_packet(packet):
            nonlocal message, current_bits, last_packet_time, burst_count
            
            if IP in packet and ICMP in packet:
                current_time = time.time()
                
                # Start of new burst
                if last_packet_time is None or (current_time - last_packet_time > idle_threshold):
                    if burst_count > 0:  # Process previous burst
                        actual_burst = burst_count // 2  # Divide by 2 to handle duplicate packets
                        print(f"Raw burst count: {burst_count}, Actual burst: {actual_burst}")
                        
                        if actual_burst == burst_size_1:
                            current_bits += "1"
                        elif actual_burst == burst_size_0:
                            current_bits += "0"
                        print(f"Current bits: {current_bits}")
                        
                        # Convert bits to character when we have 8 bits
                        if len(current_bits) == 8:
                            char = self.convert_eight_bits_to_character(current_bits)
                            message += char
                            current_bits = ""
                            print(f"Message so far: {message}")
                    burst_count = 1
                else:
                    burst_count += 1
                
                last_packet_time = current_time

        def stop_filter(packet):
            """Stop sniffing when message ends with period"""
            return message.endswith(".")

        print("Starting to receive packets...")
        sniff(iface=interface, filter="icmp", prn=process_packet, stop_filter=stop_filter)
        
        print(f"Final message: {message}")
        self.log_message(message, log_file_name)