import subprocess
import multiprocessing
import atexit
import os

from misc.zigsniff_utilities import report

def fifo_available(fifo_path: str, path: str):

    if os.path.exists(fifo_path):
        report("\tCapture point already exists", path)
        return 0
    else:
        try:
            os.mkfifo(fifo_path, 0o600)
            report("\tCapture point created", path)
            return 0
        except Exception as e:
            report("\tFailed to create capture point:\n" + str(e), path)
            return 1

def run_whsniff(channel: int, fifo_path: str, pcap_path: str, path: str):
    try:
        # check for fifo file or create one
        if fifo_available(fifo_path, path) == 1:
            exit()

        command = f"whsniff -c {channel} | tee {fifo_path} >> {pcap_path}"  # Command that is used to capture zigbee data. its run into a fifo file so pyshark can capture and a pcap for record keeping
        process = subprocess.run(command, capture_output=True, text=True, check=True, shell=True)
        report(f"Whsniff started: {process.returncode}", path)

    except Exception as e:
        report(f"Whsniff error occurred: {e}", path)
        exit()

# Function to start the process
def start_whsniff_process(channel: int, fifo_path: str, pcap_path: str, path: str) -> multiprocessing.Process:
    process = multiprocessing.Process(target=run_whsniff, args=(channel, fifo_path, pcap_path, path))
    process.start()

    # Register the process termination when the program exits
    atexit.register(lambda: terminate_whsniff_process(process))
    return process

# Function to terminate the process
def terminate_whsniff_process(process) -> None:
    if process.is_alive():
        process.terminate()
        process.join()  # Ensure the process has terminated before exiting