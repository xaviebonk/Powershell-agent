import socket
import json
import time

#networking configuration 
LOGSTASH_HOST = "192.168.186.131"  # Logstash IP
LOGSTASH_PORT = 5044         # TCP input port
FILE_TO_SEND = "/var/log/audit/audit.log"   # Your raw auditd log file
DELAY_BETWEEN_LINES = 0.1    # Seconds between sending lines (optional)


#Function to send JSON lines
def send_line(sock, line):
    # Strip newlines
    line = line.strip()
    if not line:
        return

    # Wrap in JSON {"message": "<raw_line>"}
    #json_data = json.dumps({"message": line})


    # testing if host.os.type ccan be added in this manner
    json_data = json.dumps({
        "message": line,
        "host":{
            "os":{
                "type":"linux"
            }
        }
    })

    print(f"[*] Sent: {json_data}")

    # Send over TCP
    sock.sendall((json_data + "\n").encode("utf-8"))  # newline separates messages

# main sender loop 
def main():
    with socket.create_connection((LOGSTASH_HOST, LOGSTASH_PORT)) as sock:
        print(f"[+] Connected to Logstash at {LOGSTASH_HOST}:{LOGSTASH_PORT}")

        with open(FILE_TO_SEND, "r") as f:
            for line in f:
                send_line(sock, line)
                #time.sleep(DELAY_BETWEEN_LINES)

        print("[+] Done sending lines")

if __name__ == "__main__":
    main()

