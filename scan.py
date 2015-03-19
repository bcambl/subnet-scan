#!/usr/bin/env python
"""
subnet-scan
============

Scan current subnet for hosts/devices and logs to csv file.
CSV Keys: "IP", "PING", "HOSTNAME", "MAC"

Inspired by: github.com/ericdorsey/HostMAC
"""
__author__ = 'Blayne Campbell'

import subprocess
import datetime
import socket
import csv
import sys
import os
import re

current_date = datetime.datetime.now().strftime('%Y-%m-%d')
current_time = datetime.datetime.now().strftime('%H-%M-%S')
logging_directory = "./logs/%s" % current_date


def setup_log():
    """ Creates logging directory for current script run
    """
    try:
        if not os.path.exists(logging_directory):
            os.makedirs(logging_directory)
        logfile = open("%s/%s.csv" % (logging_directory, current_time), "ab+")
        wr = csv.writer(logfile)
        headers = ["IP", "PING", "HOSTNAME", "MAC"]
        wr.writerow(headers)
    except OSError as e:
        print(e)


def validate_ip(ip):
    """ Validates ipv4 IP address via regex
    :param ip: IP address
    :return: True/False validation
    """
    ipregex = '\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)' \
              '{3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b'
    valid_ip = re.match(ipregex, ip)
    if valid_ip:
        return True
    else:
        return False


def get_hostname(ip):
    """ Get hostname via IP address
    :param ip: IP Address
    :return: hostname
    """
    try: 
        homename = socket.gethostbyaddr(ip)[0]
        return homename
    except socket.error:
        return "unknown"


def get_ping(ip):
    """ Ping IP and return latency
    :param ip: IP address
    :return: latency
    """
    ping_command = "ping -c 1 " + ip
    ping = subprocess.Popen(ping_command,
                            shell=True, stdout=subprocess.PIPE)
    ping_output = ping.communicate()
    ping_found = re.search(r'time=(.*\sms)?', ping_output[0])
    if ping_found:
        ping_result = ping_found.group(1)
    else:
        ping_result = 'Host Unreachable'
    return ping_result


def get_mac(ip):
    """ Get MAC address via IP
    :param ip: IP address
    :return: MAC address
    """
    arp_command = "arp -a " + ip
    arp = subprocess.Popen(arp_command, shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    arp_output = arp.communicate()
    find_mac = re.search(r'\s(([0-9A-F]{2}[:-]){5}([0-9A-F]{2}))?\s',
                         arp_output[0].upper())
    if find_mac:
        return find_mac.group(1)
    else:
        return 'unknown'


def check_ip(ip):
    """ Collect all information for given IP address
    :param ip: IP Address
    :return: [ip_address, ping_ms, hostname, mac_address]
    """
    name = get_hostname(ip)
    if name != 'unknown':
        ping = get_ping(ip)  # Only ping if hostname resolves
    else:
        ping = 'unknown'
    mac = get_mac(ip)
    csv_out = [ip, ping, name, mac]
    print(', '.join(csv_out))
    return csv_out


def main(ip, scan=False):
    """
    :param ip: IP Address
    :param scan: If True, scan entire IP range
    :return:
    """
    try:
        logfile = open("%s/%s.csv" % (logging_directory, current_time), "ab+")
    except IOError as (errno, strerror):
        print("Could not open %s/%s.csv: I/O error(%s): %s"
              % (logging_directory, current_time, errno, strerror))
        sys.exit()
    write_csv = csv.writer(logfile)
    if scan:
        network = re.match(r'((\d{,3}\.\d{,3}\.\d{,3})\.)?(\d{,3})', ip)
        for i in range(1, 255):
            ip_address = network.group(1) + str(i)
            csv_out = check_ip(ip_address)
            write_csv.writerow(csv_out)
    else:
        csv_out = check_ip(ip)
        write_csv.writerow(csv_out)
    logfile.close()


def detect_ip(ip_address=None):
    """ Create a UDP socket connection to populate getsockname()
    The address does not actually need to resolve ie: 1.2.3.4
    :param ip_address: Default IP of None
    :return: Detected IP or a manually entered valid IP
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('1.2.3.4', 0))
        ip_address = s.getsockname()[0]
    except socket.error:
        print("Unable to your detect IP..\n"
              "Please provide an IP from your subnet")
        while True:
            if not ip_address or not validate_ip(ip_address):
                ip_address = raw_input("IP: ")
            else:
                break
        else:
            sys.exit("Quitting..")
    finally:
        s.close()
    return ip_address


if __name__ == "__main__":
    while True:
        print("\nSubnet-Scanner\n-----------------\n\n"
              "Detected IP: %s\n"
              "1) Continue with detected IP (creates 254 entries)\n"
              "2) Enter another IP (creates one entry)\n"
              "3) Exit\n" % detect_ip())
        try:
            answer = int(raw_input("Selection? "))
            if answer == 1:
                setup_log()
                main(detect_ip(), scan=True)
                sys.exit()
            elif answer == 2:
                provided_ip = raw_input("Input IP: ")
                if validate_ip(provided_ip):
                    setup_log()
                    main(provided_ip)
                    sys.exit()
                else:
                    print "Invalid IP"
            elif answer == 3:
                sys.exit()
        except KeyboardInterrupt:
            sys.exit('Scanner exited by user..')
        except ValueError:
            print
            print "Invalid entry"
