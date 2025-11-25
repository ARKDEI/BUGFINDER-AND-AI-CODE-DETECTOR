import os

def run_user_code(code):  # eval_usage
    return eval(code)

def dangerous(cmd):  # shell_injection
    os.system("sh -c '" + cmd + "'")
