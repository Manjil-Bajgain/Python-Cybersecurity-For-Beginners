## USED THINGS in  this code is:
"""" 1). Python Dictionary -> To define the set of rule
     2). Function to generate the Ip address->Simulate  traffic  """

import random

def generate_random_ip():
    return f"192.168.1.{random.randint(0,20)}"

def check_firewall_rules(ip,rules):
    for rule_ip, action in rules.items():
        if ip==rule_ip:
            return action
    return "allow"

def main():
    firewall_rules={
        "192.168.1.1":"block",
        "192.168.1.4":"block",
        "192.168.1.9":"block",
        "192.168.1.13":"block",
        "192.168.1.16":"block",
        "192.168.1.19":"block",
    }

    for _ in range(12):
        ip_addresses=generate_random_ip()
        action=check_firewall_rules(ip_addresses,firewall_rules)
        random_number=random.randint(0,9999)
        print(f"IP:{ip_addresses}, Action:{action}, Random:{random_number}")

if __name__=="__main__":
    main()


