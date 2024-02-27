## Libraries
import psutil
import argparse
from ip2geotools.databases.noncommercial import DbIpCity
from collections import Counter
from time import strftime, sleep
from random import randint
from termcolor import colored


## Version
__version__ = "1.2"

## Parameters
parser = argparse.ArgumentParser(prog='Connections Scan', description='Scan connections through processes listing their names, pid and their ip. You can also look for geographical information about the connections. Save your scan in a report.')

parser.add_argument("-g", "--ghost", action="store_true", help="Enable ghost mode hidding every output from the terminal, add a -s [FILE] to see the output in a file.")
parser.add_argument("-i", "--ip", action="store_true", help= "Enable more detail information about ip geolocation; region, country, city, and coordinates.")
parser.add_argument("-s", "--save", action="store", help= "The scan will be saved in a file, you can choose the name of the file.")

argument = parser.parse_args()


## Process "database"
ps_amount = 0
ps_name_list = []
ps_ip_list = []
ps_id_list = []


## Process listing function
def process_listing():
    ## Global variables for recording process data
    global ps_amount 
    global ps_name_list
    global ps_ip_list
    global ps_id_list

    ## Error messages and managment
    try:
        ## Checking all inet connections, and checking for ESTABLISHED connections
        connections = psutil.net_connections(kind="all")
        for conn in connections:
            ## If connection is established, print information about it and record the info
            if conn.status == "ESTABLISHED" or conn.status == None:
                if not argument.ghost:
                    print(colored("\nCONNECTION FOUND", "cyan"))
                    print("======================================================")
            
                pid = conn.pid
                ip = conn.raddr.ip

                process = psutil.Process(pid)
                if not argument.ghost:
                    print(f"PID: {pid}")
                    print(f"Name: {process.name()}")
                    print(f"Status: " + colored(f"{process.status()}", "green"))

                ## Printing extra ip information
                if argument.ip:
                    info = DbIpCity.get(ip, api_key="free")

                    ip_geolocation = {"IP": info.ip_address, "City": info.city, "Region": info.region, "Country": info.country, "Latitude": info.latitude, "Longitude": info.longitude}
                    if not argument.ghost:
                        print(f"IP: " + colored(f"{info.ip_address}", "yellow"))
                        print(f"City: {info.city}")
                        print(f"Region: {info.region}")
                        print(f"Country: {info.country}")
                        print(f"Latitude: {info.latitude}")
                        print(f"Longitude: {info.longitude}")

                    ps_ip_list.append(ip_geolocation)
                else:
                    if not argument.ghost:
                        print(f"IP: {ip}")
                    ## Saving processes data
                    ps_ip_list.append(ip)
                ps_amount += 1 
                ps_name_list.append(process.name())
                ps_id_list.append(pid)
                if not argument.ghost:
                    print("======================================================")

                sleep(0.5)
    except psutil.AccessDenied:
        print("ERROR: Unable to access processes, try using command priviledges with sudo")


## Report creator
def report():
    ## Pick name of the file the user want and redirect the output to that file
    global filename
    filename = argument.save

    ## Variables for counting repeat ids and names
    count_ids = Counter(ps_id_list)
    printed_ids = set()
    count_names = Counter(ps_name_list)
    printed_names = set()

    ## Date, Hour and an "ID" of the report
    current_date = strftime("%d/%m/%Y")
    current_hour = strftime("%H:%M")
    random_report_id = randint(1, 99999)

    ## Writing the report on the file 'file'
    with open(filename, 'w') as file:
        print("======================================================", file=file)
        print(f"REPORT", file=file)
        print(f"Date: {current_date}", file=file)
        print(f"Hour: {current_hour}", file=file)
        print(f"Identifier: {random_report_id}", file=file)
        print("======================================================", file=file)
        print(f"Processes Amount: {ps_amount}", file=file)
        print(f"PID list: ", file=file)
        for identifier in ps_id_list:
            if identifier not in printed_ids:
                print(f"- {identifier} x{count_ids[identifier]}", file=file)
                printed_ids.add(identifier)

        print(f"\nServices: ", file=file)
        for service in ps_name_list:
            if service not in printed_names:
                print(f"- {service} x{count_names[service]}", file=file)
                printed_names.add(service)

        print(f"\nIP List: ", file=file)
        if argument.ip:
            for ip_info in ps_ip_list:
                print("------------------------------------------------------", file=file)
                print(f"IP: {ip_info['IP']}", file=file)
                print(f"City: {ip_info['City']}", file=file)
                print(f"Region: {ip_info['Region']}", file=file)
                print(f"Country: {ip_info['Country']}", file=file)
                print(f"Latitude: {ip_info['Latitude']}", file=file)
                print(f"Longitude: {ip_info['Longitude']}", file=file)
        else:
            for ip_info in ps_ip_list:
                print(f"- {ip_info}", file=file)
        print("======================================================", file=file)


def encrypt_report():
    print("Hello world!!!")

## Principal logic
if __name__ == "__main__":  
    process_listing()   
    ## Extra logic for saving a report   
    if argument.save:
        report()
        ## Hide prints if the ghost mode is on
        if not argument.ghost:
            print(colored(f"\n[!] REPORT saved in ./{filename}", "magenta"))
            
