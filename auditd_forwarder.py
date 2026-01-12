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
def send_line(sock, line, file_type, previous_sequence_number, possible_file_path ,file_path_dict,args_dict):
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
        #file_path = re.search(r'type=PATH.*?\bname=([^\s]+)', line)
        file_path = re.search(r'type=PATH.*?\bname="?([^"\s]+)"?', line)
        ppid_match = re.search(r'\bppid=(\d+)\b', line)
        args = re.findall(r'a\d+="([^"]*)"', line)

        Delete_file_pattern = re.search(
            r'type=PATH\b.*\bname="?([^"\s]+)"?\b.*\bnametype=(DELETE|CREATED)\b',
            line
        )


        

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
        if ppid_match:
            ppid = ppid_match.group(1)
            result = subprocess.run(
                ["ps", "-p", ppid, "-o", "comm=,exe="],
                capture_output=True,
                text=True
            )

            if result.returncode != 0 or not result.stdout.strip():
                print("Parent process not found")
                comm = "-"
                exe = "-"
            else:
                comm,exe = result.stdout.strip().split(None,1)


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
        
        
        #add host.id,process.parent.executable,process.parent.name
        json_dict = json.loads(json_data)
        json_dict["host"]["id"] = "1234567890abcdef"
        #ensure nested keys exist before assigning
        if ppid_match:
            if "process" not in json_dict:
                json_dict["process"] = {}
            if "parent" not in json_dict["process"]:
                json_dict["process"]["parent"] = {}
            json_dict["process"]["parent"]["executable"] = exe
            json_dict["process"]["parent"]["name"] = comm
        
        json_data = json.dumps(json_dict)

        if args:
            args_dict[sequence_number.group(1)] = args
        
        if sequence_number and sequence_number.group(1) in args_dict:
            json_dict = json.loads(json_data)
            if "process" not in json_dict:
                json_dict["process"] = {}
            json_dict["process"]["args"] = args_dict[sequence_number.group(1)]
            json_data = json.dumps(json_dict)



        #Store file path and file name based on sequence number
        if file_path and sequence_number:
            #file_path_dict[sequence_number.group(1)] = file_path.group(1)
            #if sequence_number.group(1) in file_path_dict:
                #if file_path_dict[sequence_number.group(1)]["override_name"] != None:
                    
            if sequence_number.group(1) not in file_path_dict:
                file_path_dict[sequence_number.group(1)] = {
                    "path": file_path.group(1),
                    "name": None,
                    "override_name": None 
                }
            
            file_path_dict[sequence_number.group(1)]["path"] = file_path.group(1)
            json_dict = json.loads(json_data)
            file_path_value = file_path_dict[sequence_number.group(1)]["path"]
            match = re.search(r'([^/]+)$', file_path_value)
            if match:
                file_name = match.group(1)
                file_path_dict[sequence_number.group(1)]["name"] = file_name

                json_dict["file"]["name"] = file_name
            if Delete_file_pattern:
                file_path_dict[sequence_number.group(1)]["override_name"] = Delete_file_pattern.group(1)

            json_dict["file"]["path"] = file_path_dict[sequence_number.group(1)]["path"]
            json_data = json.dumps(json_dict)

        if sequence_number and sequence_number.group(1) in file_path_dict:
            json_dict = json.loads(json_data)
            if file_path_dict[sequence_number.group(1)]["override_name"]:
                json_dict["file"]["name"] = file_path_dict[sequence_number.group(1)]["override_name"]
            else:
                #file_path_value = file_path_dict[sequence_number.group(1)]
                #match = re.search(r'([^/]+)$', file_path_value)
                #if match:
                    #file_name = match.group(1)

                    #json_dict["file"]["name"] = file_name
                json_dict["file"]["name"] = file_path_dict[sequence_number.group(1)]["name"]
            json_dict["file"]["path"] = file_path_dict[sequence_number.group(1)]["path"]
                #json_dict["file"]["name"] = file_name
            json_data = json.dumps(json_dict)

        #if sequence_number.group(1) in file_path_dict:
            #json_dict = json.loads(json_data)
            #json_dict["file"]["path"] = file_pat
            # h_dict[sequence_number.group(1)]
            #json_data = json.dumps(json_dict)

        #if previous_sequence_number == sequence_number.group(1):
            #if possible_file_path:
                #file_path_to_keep  = possible_file_path

        #if previous_sequence_number and possible_file_path != None:
            #if previous_sequence_number == sequence_number.group(1):
                #json_dict = json.loads(json_data)
                #json_dict["file"]["path"] = possible_file_path
               # json_data = json.dumps(json_dict)


    print(f"[*] Sent: {json_data}")

    # Send over TCP
    sock.sendall((json_data + "\n").encode("utf-8"))  # newline separates messages

    #previous_sequence_number = sequence_number.group(1) if sequence_number else None
    #possible_file_path = file_path.group(1) if file_path else None
    #possible_file_path = file_path.group(1) if file_path else None
    previous_sequence_number = "nothing"
    possible_file_path = "nothing"
    return previous_sequence_number, possible_file_path , file_path_dict,args_dict
   

# main sender loop 
def main():
    with socket.create_connection((LOGSTASH_HOST, LOGSTASH_PORT)) as sock:
        print(f"[+] Connected to Logstash at {LOGSTASH_HOST}:{LOGSTASH_PORT}")

        previous_sequence_number = None
        possible_file_path = None

        file_path_dict = {}

        args_dict = {}


        with open(FILE_TO_SEND, "r") as f:
            print("[*] Reading file ...")
            lines = f.readlines()
            for line in reversed(lines):
                previous_sequence_number, possible_file_path, file_path_dict, args_dict = send_line(sock, line, file_type,previous_sequence_number, possible_file_path,file_path_dict,args_dict)
                #file_path_dict[previous_sequence_number] = possible_file_path
                #time.sleep(DELAY_BETWEEN_LINES)
            for key, value in file_path_dict.items():
                print(f"{key} -> {value}")
            for key, value in args_dict.items():
                print(f"{key} -> {value}")
            
            


        print("[+] Done sending lines")

if __name__ == "__main__":
    main()

