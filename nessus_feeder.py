import re
import subprocess
import os 


def cut(file1):
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    with open(file1) as fh:
        fstring = fh.readlines()
    # initializing the list object
    lst=[]
  
    # extracting the IP addresses
    for line in fstring:
       print(pattern.search(line)[0])
    



def scan(ips_file):
    # opening and reading the file 
    
    
    with open(ips_file) as ip:
        ips = ip.readlines()
    ip_count=0
    for i in ips:
        print(ip_count)
        print("Scanning : "+ i)
        if i.isspace():
            continue
        else:
            out = os.system('nmap -sn -n  -iL {1} >> file{0}.txt'.format(ip_count,ips_file))
            ip_count = ip_count + 1
        
   
        #print(ips[i])
if __name__ == "__main__":

    scan("./targets2.txt")
