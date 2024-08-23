import json
import time
import socket
import os.path

class config:
    def __init__(self):
        self.channel = None
        self.report_period = None
        self.fifo_file_path = None
        self.reload_config()

    #@staticmethod
    def reload_config(self):
        global data

        with open("zigsniff_config.json", "r") as json_file:
            data = json.load(json_file)

        self.fifo_file_path = data['paths']['fifo_path']
        self.channel = data['channel']
        self.report_period = data['report_period']

    def change_variable(self, variable, change):
        pass