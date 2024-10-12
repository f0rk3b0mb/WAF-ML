from scapy.all import sniff, TCP, IP, Raw
import urllib
import joblib
from utils import block_ip
from ML.waf import WAF
from database import log_request
from web.main import app


def extract_url(packet):
    if packet.haslayer(Raw):  # Check if the packet has a payload
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')

            # Only consider HTTP GET requests
            if payload.startswith('GET'):
                # Split payload to get the request line (first line contains the URL)
                request_line = payload.split('\n')[0]
                # Extract the URL from the request line
                url = request_line.split(' ')[1]

                # Handle URL encoding
                url = urllib.parse.unquote(url)  # Decode any URL-encoded characters
                print(f"Extracted URL: {url}")
                return url
        except Exception as e:
            print(f"Error extracting URL: {e}")

    return None


def handle_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        url = extract_url(packet)
        log_request(source_ip, url)

        if url:
            try:
                # Make prediction using your WAF's ML model
                result = w.predict([url])
                if result[0]['res'] == 'Malicious request':
                    print(f"Blocked malicious URL: {url} from {source_ip}")
                    # Implement logic to block the IP or drop the packet (optional)
                    block_ip(source_ip)
                else:
                    print(f"Allowed URL: {url} from {source_ip}")
                    # Optionally log the allowed traffic for analysis

            except Exception as e:
                print(f"Error during prediction: {e}")





if __name__ == '__main__':
    with open('ML/lgs.pickle','rb') as input:
        w = joblib.load('ML/lgs.pickle')
    print("Model loaded succesfully :)")
    print("")
    
    # Start sniffing HTTP traffic (port 80)
    sniff(filter="tcp port 80", prn=handle_packet, store=0,iface=['lo','wlp3s0'])
    print("Waf listening on port 80 ...")

