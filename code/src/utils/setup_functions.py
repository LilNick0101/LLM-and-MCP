import datetime
import os
import shutil

from utils.file_utils import ensure_directory_exists

PARENT_PATH = os.path.dirname(os.path.abspath(__file__ + "/.."))
TEMPLATE_PATH = os.path.join(PARENT_PATH, "templates")
RESULTS_PATH = os.path.join(PARENT_PATH, "exploit-pocs")

class PrepareHooks:

    @staticmethod
    def prepare_app_common(temp_dir, number) -> str:

        ensure_directory_exists(temp_dir)
        shutil.copytree(TEMPLATE_PATH + "/app", temp_dir + "/app")
        shutil.copyfile(TEMPLATE_PATH + f"/rules/{number}/MainActivity.java", temp_dir + "/app/app/src/main/java/com/example/exploittemplate/MainActivity.java")
        
        shutil.copyfile(TEMPLATE_PATH + f"/rules/{number}/verify.py", temp_dir + "/verify.py")
        return temp_dir + "/app/"
    
    @staticmethod
    def copy_fake_cert(temp_dir):
        ensure_directory_exists(temp_dir + "/certs")
        shutil.copyfile(PARENT_PATH + "/certs/fake_cert.pem", temp_dir + "/fake_cert.pem")
        shutil.copyfile(PARENT_PATH + "/certs/fake_key.pem", temp_dir + "/fake_key.pem")
        return temp_dir + "/certs/"

    @staticmethod
    def prepare_rule_1(temp_dir) -> str:
        return PrepareHooks.prepare_app_common(temp_dir, 1)
    
    @staticmethod
    def prepare_rule_4(temp_dir) -> str:

        ensure_directory_exists(temp_dir + "/Sdk")
        shutil.copyfile(TEMPLATE_PATH + "/rules/4/EvilSdk.java", temp_dir + "/Sdk/EvilSdk.java")
        shutil.copyfile(TEMPLATE_PATH + f"/rules/4/verify.py", temp_dir + "/verify.py")
        return temp_dir + "/Sdk/"

    @staticmethod
    def prepare_rule_5(temp_dir) -> str:

        shutil.copytree(TEMPLATE_PATH + "/rules/5/mitm", temp_dir + "/mitm")
        shutil.copyfile(TEMPLATE_PATH + f"/rules/5/verify.py", temp_dir + "/verify.py")
        return temp_dir + "/mitm/"

    @staticmethod
    def prepare_rule_6(temp_dir) -> str:
        ensure_directory_exists(temp_dir + "/page")
        shutil.copyfile(TEMPLATE_PATH + "/rules/6/page/attack.html", temp_dir + "/page/attack.html")
        shutil.copyfile(TEMPLATE_PATH + "/rules/6/verify.py", temp_dir + "/verify.py")
        return temp_dir + "/page/"
    
    @staticmethod
    def prepare_rule_8(temp_dir) -> str:
        return PrepareHooks.prepare_app_common(temp_dir, 8)

    @staticmethod
    def prepare_rule_9(temp_dir) -> str:
        return PrepareHooks.prepare_app_common(temp_dir, 9)

    @staticmethod
    def prepare_rule_10(temp_dir) -> str:

        ensure_directory_exists(temp_dir + "/Sdk")
        shutil.copyfile(TEMPLATE_PATH + "/rules/10/EvilSdk.java", temp_dir + "/Sdk/EvilSdk.java")
        shutil.copyfile(TEMPLATE_PATH + f"/rules/10/verify.py", temp_dir + "/verify.py")
        return temp_dir + "/Sdk/"

    @staticmethod
    def prepare_rule_11(temp_dir) -> str:
        return PrepareHooks.prepare_app_common(temp_dir, 11)

    @staticmethod
    def prepare_rule_13(temp_dir) -> str:
        return PrepareHooks.prepare_app_common(temp_dir, 13)

    @staticmethod
    def prepare_rule_15(temp_dir) -> str:

        ensure_directory_exists(temp_dir + "/Sdk")
        shutil.copyfile(TEMPLATE_PATH + "/rules/15/EvilSdk.java", temp_dir + "/Sdk/EvilSdk.java")
        shutil.copyfile(TEMPLATE_PATH + f"/rules/15/verify.py", temp_dir + "/verify.py")
        return temp_dir + "/Sdk/"

    @staticmethod
    def prepare_rule_16(temp_dir) -> str:
        return PrepareHooks.prepare_app_common(temp_dir, 16)

    @staticmethod
    def prepare_rule_17(temp_dir) -> str:
        return PrepareHooks.prepare_app_common(temp_dir, 17)

    @staticmethod
    def prepare_rule_18(temp_dir) -> str:
        return PrepareHooks.prepare_app_common(temp_dir, 18)

    @staticmethod
    def prepare_rule_19(temp_dir) -> str:
        return PrepareHooks.prepare_app_common(temp_dir, 19)
    
    @staticmethod
    def prepare_rule_20(temp_dir) -> str:
        return PrepareHooks.prepare_app_common(temp_dir, 20)

    @staticmethod
    def prepare_rule_21(temp_dir) -> str:
        ensure_directory_exists(temp_dir + "/exploit")
        return temp_dir + "/exploit"

    @staticmethod
    def prepare_rule_22(temp_dir) -> str:
        return PrepareHooks.prepare_app_common(temp_dir, 22)

    @staticmethod
    def prepare_rule_23(temp_dir) -> str:
        ensure_directory_exists(temp_dir + "/exploit")
        return temp_dir + "/exploit/"
    
    @staticmethod
    def prepare_rule_24(temp_dir) -> str:
        mitm_dir = temp_dir + "/mitm/"
        shutil.copytree(TEMPLATE_PATH + "/rules/24/mitm", mitm_dir)
        shutil.copyfile(TEMPLATE_PATH + f"/rules/24/verify.py", temp_dir + "/verify.py")
        PrepareHooks.copy_fake_cert(temp_dir)
        return mitm_dir

    @staticmethod
    def prepare_rule_25(temp_dir) -> str:
        mitm_dir = temp_dir + "/mitm/"
        shutil.copytree(TEMPLATE_PATH + "/rules/25/mitm", mitm_dir)
        shutil.copyfile(TEMPLATE_PATH + f"/rules/25/verify.py", temp_dir + "/verify.py")
        PrepareHooks.copy_fake_cert(temp_dir)
        return mitm_dir

    @staticmethod
    def prepare_rule_27(temp_dir) -> str:
        shutil.copytree(TEMPLATE_PATH + "/rules/27/mitm", temp_dir + "/mitm")
        shutil.copyfile(TEMPLATE_PATH + f"/rules/27/verify.py", temp_dir + "/verify.py")
        return temp_dir + "/mitm/"

    @staticmethod
    def prepare_rule_28(temp_dir) -> str:
        ensure_directory_exists(temp_dir + "/exploit")
        return temp_dir + "/exploit/"

    @staticmethod
    def prepare_rule_29(temp_dir) -> str:
        ensure_directory_exists(temp_dir + "/exploit")
        return temp_dir + "/exploit"

    @staticmethod
    def prepare_rule_30(temp_dir) -> str:
        return PrepareHooks.prepare_app_common(temp_dir, 30)

    @staticmethod
    def prepare_rule_31(temp_dir) -> str:
        return PrepareHooks.prepare_app_common(temp_dir, 31)

class PostHooks:

    package_name = ""

    @staticmethod
    def move_to_new_dir(temp_dir, rule, prefix : str) -> str:
        ensure_directory_exists(os.path.join(RESULTS_PATH, f"{PostHooks.package_name}/{rule}"))
        final_path = os.path.join(RESULTS_PATH, f"{PostHooks.package_name}/{rule}/" + prefix + "_" + datetime.datetime.now().strftime("%Y_%m_%d-%H_%M_%S"))

        shutil.move(temp_dir, final_path)
        os.chmod(final_path + "/verify.py", 0o755)
        return final_path

    @staticmethod
    def save_app_common(temp_dir, rule, prefix : str) -> str:
        return PostHooks.move_to_new_dir(temp_dir, rule, prefix)

    @staticmethod
    def post_rule_1(temp_dir, prefix : str) -> str:
        return PostHooks.move_to_new_dir(temp_dir, "1", prefix)
    
    @staticmethod
    def post_rule_4(temp_dir, prefix : str) -> str:
        return PostHooks.move_to_new_dir(temp_dir, "4", prefix)

    @staticmethod
    def post_rule_5(temp_dir, prefix : str) -> str:
        return PostHooks.move_to_new_dir(temp_dir, "5", prefix)

    @staticmethod
    def post_rule_6(temp_dir, prefix : str) -> str:
        return PostHooks.move_to_new_dir(temp_dir, "6", prefix)
    
    @staticmethod
    def post_rule_7(temp_dir, prefix : str) -> str:
        return PostHooks.move_to_new_dir(temp_dir, "7", prefix)
    
    @staticmethod
    def post_rule_8(temp_dir, prefix : str) -> str:
        return PostHooks.save_app_common(temp_dir, "8", prefix)

    @staticmethod
    def post_rule_9(temp_dir, prefix : str) -> str:
        return PostHooks.save_app_common(temp_dir, "9", prefix)
    
    @staticmethod
    def post_rule_10(temp_dir, prefix : str) -> str:
        return PostHooks.move_to_new_dir(temp_dir, "10", prefix)
    
    @staticmethod
    def post_rule_11(temp_dir, prefix : str) -> str:
        return PostHooks.save_app_common(temp_dir, "11", prefix)
    
    @staticmethod
    def post_rule_13(temp_dir, prefix : str) -> str:
        return PostHooks.save_app_common(temp_dir, "13", prefix)

    @staticmethod
    def post_rule_15(temp_dir, prefix : str) -> str:
        return PostHooks.move_to_new_dir(temp_dir, "15", prefix)

    @staticmethod
    def post_rule_16(temp_dir, prefix : str) -> str:
        return PostHooks.save_app_common(temp_dir, "16", prefix)

    @staticmethod
    def post_rule_17(temp_dir, prefix : str) -> str:
        return PostHooks.save_app_common(temp_dir, "17", prefix)
    
    @staticmethod
    def post_rule_18(temp_dir, prefix : str) -> str:
        return PostHooks.save_app_common(temp_dir, "18", prefix)

    @staticmethod
    def post_rule_19(temp_dir, prefix : str) -> str:
        return PostHooks.save_app_common(temp_dir, "19", prefix)
    
    @staticmethod
    def post_rule_20(temp_dir, prefix : str) -> str:
        return PostHooks.save_app_common(temp_dir, "20", prefix)
    
    @staticmethod
    def post_rule_21(temp_dir, prefix : str) -> str:
        return PostHooks.move_to_new_dir(temp_dir, "21", prefix)
    
    @staticmethod
    def post_rule_22(temp_dir, prefix : str) -> str:
        return PostHooks.save_app_common(temp_dir, "22", prefix)

    @staticmethod
    def post_rule_23(temp_dir, prefix : str) -> str:
        return PostHooks.move_to_new_dir(temp_dir, "23", prefix)
    
    @staticmethod
    def post_rule_24(temp_dir, prefix : str) -> str:
        return PostHooks.move_to_new_dir(temp_dir, "24", prefix)
    
    @staticmethod
    def post_rule_25(temp_dir, prefix : str) -> str:
        return PostHooks.move_to_new_dir(temp_dir, "25", prefix)

    @staticmethod
    def post_rule_27(temp_dir, prefix : str) -> str:
        final_path = PostHooks.move_to_new_dir(temp_dir, "27", prefix)
        return final_path
    
    @staticmethod
    def post_rule_28(temp_dir, prefix : str) -> str:
        return PostHooks.move_to_new_dir(temp_dir, "28", prefix)

    @staticmethod
    def post_rule_29(temp_dir, prefix : str) -> str:
        return PostHooks.move_to_new_dir(temp_dir, "29", prefix)
    
    @staticmethod
    def post_rule_30(temp_dir, prefix : str) -> str:
        return PostHooks.save_app_common(temp_dir, "30", prefix)

    @staticmethod
    def post_rule_31(temp_dir, prefix : str) -> str:
        return PostHooks.save_app_common(temp_dir, "31", prefix)