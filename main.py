import os
import sys
import re
import subprocess

KANALYZER = os.path.join(os.path
                         .dirname(__file__), "build/lib/kanalyzer")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("step1: python3 ./main.py build")
        print("step2: python3 ./main.py run")
        print("step3: python3 ./main.py analysis")
    if sys.argv[1] == "build":
        subprocess.check_call("./build-llvm.sh", shell=True)
        subprocess.check_call("./getlinux.sh", shell=True)
    
        subprocess.check_call("cd IRDumper && make", shell=True)
        subprocess.check_call("make all", shell=True)
        subprocess.check_call("./irgen.sh", shell=True)
    elif sys.argv[1] == "run":
        cmd  = f'find ./linux -type f -name "*.bc" -exec {KANALYZER} {{}} + '
        log_file = "run.log"
        with open(log_file, 'w') as log:
            subprocess.check_call(cmd, shell=True, stdout=log, stderr=subprocess.STDOUT, text=True)
    elif sys.argv[1] == "analysis":
        with open("run.log", "r") as f:
            data = f.readlines()
    
        icall = 0
        icall_with_target = 0
        icall_target = 0
        address_taken = 0
        mlta_call = 0
        mlta_target = 0
        olta_call = 0
        olta_target = 0
        file_cnt = 0
        for line in data:
            if line.find("Total ") >= 0:
                pattern = r"Total (\d+) file\(s\)"
                match = re.search(pattern, line)
                if match:
                    total_files = match.group(1)
                    file_cnt += int(total_files)
            elif line.find("# Number of indirect calls:") >= 0:
                icall += int(line[27:].strip())
            elif line.find("# Number of indirect calls with targets:") >= 0:
                icall_with_target += int(line[40:].strip())
            elif line.find("# Number of indirect-call targets:") >= 0:
                icall_target += int(line[34:].strip())
            elif line.find("# Number of address-taken functions:") >= 0:
                address_taken += int(line[36:].strip())
            elif line.find("# Number of multi-layer calls:") >= 0:
                mlta_call += int(line[30:].strip())
            elif line.find("# Number of multi-layer targets:") >= 0:
                mlta_target += int(line[32:].strip())
            elif line.find("# Number of one-layer calls:") >= 0:
                olta_call += int(line[28:].strip())
            elif line.find("# Number of one-layer targets:") >= 0:
                olta_target += int(line[30:].strip())
        
        print(f"file count: {file_cnt}")
        print(f"icall: {icall}")
        print(f"icall_with_target: {icall_with_target}")
        print(f"icall_target: {icall_target}")
        print(f"address_taken: {address_taken}")
        print(f"mlta_call: {mlta_call}")
        print(f"mlta_target: {mlta_target}")
        print(f"olta_call: {olta_call}")
        print(f"olta_target: {olta_target}")

    