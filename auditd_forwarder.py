import socket
import json
import time
import sys
import subprocess
import re

# Ensure pyfiglet is installed
try:
    import pyfiglet
except ImportError:
    print("[*] pyfiglet not found, installing...")
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", "pyfiglet"
    ])
    import pyfiglet  # retry after install

# ASCII Art Title
text = "event-forwarder"
ascii_art = pyfiglet.figlet_format(text, font="smslant")

print(ascii_art)


file_type = input("Enter the type of log file to send (auditd/syslog/auth): ").strip().lower()

match file_type:
    case "auditd":
        FILE_TO_SEND = "/var/log/audit/audit.log"
        LOGSTASH_PORT = 5044
    case "syslog":
        FILE_TO_SEND = "/var/log/syslog"
        LOGSTASH_PORT = 5045

    case "auth":
        FILE_TO_SEND = "/var/log/auth.log"
        LOGSTASH_PORT  = 5046
    case _:
        print("Invalid log type. Defaulting to auditd.")
        FILE_TO_SEND = "/var/log/audit/audit.log"
        LOGSTASH_PORT = 5044


#networking configuration 
LOGSTASH_HOST = "192.168.186.131"  # Logstash IP
#LOGSTASH_PORT = 5044         # TCP input port
#FILE_TO_SEND = "/var/log/audit/audit.log"   # Your raw auditd log file
DELAY_BETWEEN_LINES = 0.1    # Seconds between sending lines (optional)
print("[*] The program by default will send auditd logs from /var/log/audit/audit.log to logstash")



#Function to send JSON lines
def send_line(sock, line, file_type, previous_sequence_number, possible_file_path):
    # Strip newlines
    line = line.strip()
    if not line:
        return

    # Wrap in JSON {"message": "<raw_line>"}
    #json_data = json.dumps({"message": line})
    if file_type != "auditd":
        json_data = json.dumps({
        "message": line,
        "host":{
            "os":{
                "type":"linux"
            }
        }
    })
        
    else:
        target_syscall = re.search(r'SYSCALL=([^\s]+)', line)
        removable_syscall = re.search(r'syscall=([^\s]+)', line)
        sequence_number = re.search(r'audit\([^:]+:(\d+)\)', line)
        file_path = re.search(r'type=PATH.*?\bname=([^\s]+)', line)
        

        if removable_syscall:
            new_syscall = target_syscall.group(1)
            line_modified = re.sub(
                r'\bsyscall=[^\s]+\b',
                f'syscall={new_syscall}',
                line
            )
            #line_without_syscall = re.sub(r'\bsyscall=[^\s]+\b', '', line).strip()
            #syscall = target_syscall.group(1)

            json_data = json.dumps({
                            "message": line_modified,
                            "host":{
                                "os":{
                                    "type":"linux"
                                }
                            },
                            "file":{
                                
                            }
                        })

        else:
            json_data = json.dumps({
                    "message": line,
                    "host":{
                        "os":{
                            "type":"linux"
                        }
                    },
                    "file":{

                    }
                })
            
        #if file_path:
            #json_dict = json.loads(json_data)
            #json_dict["file"]["path"] = file_path.group(1)
            #json_data = json.dumps(json_dict)

        if previous_sequence_number == sequence_number.group(1):
            if possible_file_path:
                file_path_to_keep  = possible_file_path

        if previous_sequence_number and possible_file_path != None:
            if previous_sequence_number == sequence_number.group(1):
                json_dict = json.loads(json_data)
                json_dict["file"]["path"] = possible_file_path
                json_data = json.dumps(json_dict)


    print(f"[*] Sent: {json_data}")

    # Send over TCP
    sock.sendall((json_data + "\n").encode("utf-8"))  # newline separates messages

    previous_sequence_number = sequence_number.group(1) if sequence_number else None
    if possible_file_path:
        if file_path_to_keep:
            possible_file_path = file_path_to_keep
        else:
            possible_file_path = file_path.group(1) if file_path else None
    
    return previous_sequence_number, possible_file_path
   

# main sender loop 
def main():
    with socket.create_connection((LOGSTASH_HOST, LOGSTASH_PORT)) as sock:
        print(f"[+] Connected to Logstash at {LOGSTASH_HOST}:{LOGSTASH_PORT}")

        previous_sequence_number = None
        possible_file_path = None

        with open(FILE_TO_SEND, "r") as f:
            print("[*] Reading file ...")
            lines = f.readlines()
            for line in reversed(lines):
                previous_sequence_number, possible_file_path = send_line(sock, line, file_type,previous_sequence_number, possible_file_path)
                #time.sleep(DELAY_BETWEEN_LINES)

        print("[+] Done sending lines")

if __name__ == "__main__":
    main()

