import os
import subprocess
import requests

API_KEY = "sk-proj-THIS_IS_A_FAKE_TEST_KEY_1234567890"

def run_command(command):
    return subprocess.run(command, shell=True)

def read_arbitrary(path):
    return open(path).read()

def send_data(url, data):
    return requests.post(url, json=data)
