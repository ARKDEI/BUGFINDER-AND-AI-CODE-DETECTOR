import os

# except_all
try:
    1 / 0
except:
    pass

# mutable_default
def add_item(item, items=[]):
    items.append(item)
    return items

# eval_usage
def run_code(s):
    return eval(s)

# shell_injection
os.system("ls " + "$(rm -rf /)")
