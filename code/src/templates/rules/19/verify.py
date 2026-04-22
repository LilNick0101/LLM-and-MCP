#!/usr/bin/env python3

import argparse
import os
import re
import time
import subprocess as subp
from androguard.core.apk import APK

ANDROID_AVD = os.getenv("ANDROID_AVD") or "Medium_Phone"

def parse_logs(logs=None):
    print(logs if logs is not None else "No logs captured.")

def check_tp(logs=None):
    if "Start proc" in logs:
        return True
    else:
        return False
    
def verify(victim_apk : str, service_name : str):

    logs = ""
    
    try:
        proc = subp.run(["adb", "logcat", "-s", "ActivityManager:V", "Exploit"], stdout=subp.PIPE, stderr=subp.PIPE, timeout=20, text=True)
        logs = proc.stdout
    except subp.TimeoutExpired as e:
        logs = getattr(e, 'output', None) or getattr(e, 'stdout', None) or ''

    if isinstance(logs, bytes):
        logs = logs.decode()

    parse_logs(logs)
    target, ok = find_service_target(victim_apk, service_name, logs)
    return 0 if ok else 1

def find_service_target(victim_apk, service_name, out):
    target = ""
    print("Looking for Start proc .* for service {{{}/{}}}".format(victim_apk, service_name))
    regex = r"Start proc .* for service {" + re.escape(victim_apk) + r'\/' + re.escape(service_name) + r"}"
    matches = re.finditer(regex, out, re.MULTILINE)
    ok = False
    for _, match in enumerate(matches, start=1):
        print("Found matching line: {}".format(match.group(0)))
        
        ok = True
    
        target += match.group(0) + "\n" # Gives us the match only

    return (target, ok)

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
    parser.add_argument("service", help="the targeted service name")
    parser.add_argument("-avd", help="the name of the avd to use (default: Medium_Phone)", default=ANDROID_AVD)
    parser.add_argument("--manual","-m",action="store_true", help="if set to true, the script will wait for the user to press enter before starting the exploit")
    args = parser.parse_args()
    return args

def main(args):
    victimApk = APK(args.victim)
    print("Building the application...")
    os.chdir("./app")
    os.system("./gradlew assembleDebug --quiet")
    print("Lauching the emulator")
    os.system(f"emulator -avd {args.avd} -no-audio -no-boot-anim &")
    if args.manual:
        input("Press Enter once the emulator is fully booted...")
    else:
        time.sleep(30)
    subp.call(["adb", "logcat", "-c"])
    time.sleep(2)
    attackerApk = APK("./app/build/outputs/apk/debug/app-debug.apk")
    install(victimApk)
    subp.call(["adb", "shell", "am", "force-stop", f"{victimApk.get_package()}"])
    uninstall(attackerApk)
    install(attackerApk)
    launch_app(attackerApk)
    #time.sleep(5)
    return verify(victimApk.get_package(), args.service)

if __name__ == "__main__":
    exit(main(parse_args()))
