#!/usr/bin/env python3

import argparse
import os
import shutil
import sys
import time
import subprocess as subp
from androguard.core.apk import APK

REPACKAGER_PATH = "../auto_repackager.sh"
ANDROID_AVD = os.getenv("ANDROID_AVD") or "Older_API"

def parse_logs(logs=None):
    print(logs if logs is not None else "No logs captured.")

def check_tp(logs=None):
    if type(logs) is not str:
        logs = str(logs)
    if "TRUE POSITIVE" in logs:
        return True
    return False
    
def verify():
    logs = ""
    
    try:
        proc = subp.run(["adb", "logcat", "-s", "Exploit"], stdout=subp.PIPE, stderr=subp.PIPE, timeout=20, text=True)
        logs = proc.stdout
    except subp.TimeoutExpired as e:
        logs = getattr(e, 'output', None) or getattr(e, 'stdout', None) or ''

    if isinstance(logs, bytes):
        logs = logs.decode()
    parse_logs(logs)
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
    parser.add_argument("-avd", help="the name of the avd to use (default: Medium_Phone)", default=ANDROID_AVD)
    parser.add_argument("--manual","-m",action="store_true", help="if set to true, the script will wait for the user to press enter before starting the exploit")
    parser.add_argument("--repackager", "-r", help="path to the repackager script (default: {})".format(os.path.abspath(REPACKAGER_PATH)), default=REPACKAGER_PATH)
    args = parser.parse_args()
    return args

def main(args):
    victimApk = APK(args.victim)
    print("Building the application...")
    os.system("{} {}".format(args.repackager, victimApk.get_package()))
    print("Lauching the emulator")
    os.system(f"emulator -avd {args.avd} -no-audio -no-boot-anim &")
    if args.manual:
        input("Press Enter once the emulator is fully booted...")
    else:
        time.sleep(30)
    attackerApk = APK("./evil.apk")
    subp.call(["adb", "logcat", "-c"])
    #launch_app(victimApk)
    uninstall(attackerApk)
    install(attackerApk)
    launch_app(attackerApk)
    #time.sleep(5)
    return verify()

if __name__ == "__main__":
    exit(main(parse_args()))
