import os
import subprocess

password = "admin123"

def run_command(user_input):
    eval(user_input)
    os.system("ls")
    subprocess.call(user_input, shell=True)