from cicflowmeter_log_collection_tool.constants import CONNECTION_PORT
from cicflowmeter_log_collection_tool.sniffer import main_import
from pickle import load
from random import choice
import socketio
import eventlet
import warnings
# from subprocess import Popen, PIPE, DEVNULL, call
from time import sleep
from multiprocessing import Process
# from pyautogui import alert
import numpy as np
from pandas import read_csv
import argparse
import psutil
from os import path
from sklearn.preprocessing import PowerTransformer, MinMaxScaler, QuantileTransformer
from pandas import DataFrame
from winotify import Notification
from json import dumps as dumps_json, load as load_json_file, dump as dump_json_file
from socket import socket as socket_socket, AF_INET as socket_AF_INET, SOCK_DGRAM as socket_SOCK_DGRAM
import subprocess


warnings.filterwarnings("ignore")  # ! might cause problems

DIRNAME = path.dirname(__file__)
LAYER1_MODEL = "xgb_layer1_quantile"
FIRST_LAYER_COLUMNS = [
    'dst_port', 'flow_duration', 'flow_byts_s', 'flow_pkts_s', 'fwd_pkts_s',
    'bwd_pkts_s', 'tot_fwd_pkts', 'tot_bwd_pkts', 'totlen_fwd_pkts',
    'totlen_bwd_pkts', 'fwd_pkt_len_max', 'fwd_pkt_len_mean',
                       'fwd_pkt_len_std', 'bwd_pkt_len_max', 'bwd_pkt_len_mean',
                       'bwd_pkt_len_std', 'pkt_len_max', 'pkt_len_mean', 'pkt_len_std',
                       'pkt_len_var', 'fwd_header_len', 'bwd_header_len', 'fwd_seg_size_min',
                       'flow_iat_mean', 'flow_iat_max', 'flow_iat_min', 'flow_iat_std',
                       'fwd_iat_tot', 'fwd_iat_max', 'fwd_iat_min', 'fwd_iat_mean',
                       'fwd_iat_std', 'bwd_iat_tot', 'bwd_iat_max', 'psh_flag_cnt',
                       'ack_flag_cnt', 'down_up_ratio', 'pkt_size_avg', 'init_fwd_win_byts',
                       'init_bwd_win_byts']

SECOND_LAYER_COLUMNS = [
    'flow_duration', 'flow_byts_s', 'flow_pkts_s', 'fwd_pkts_s',
    'bwd_pkts_s', 'tot_fwd_pkts', 'tot_bwd_pkts', 'totlen_fwd_pkts',
    'totlen_bwd_pkts', 'fwd_pkt_len_max', 'fwd_pkt_len_min',
    'fwd_pkt_len_mean', 'fwd_pkt_len_std', 'bwd_pkt_len_max',
    'bwd_pkt_len_min', 'bwd_pkt_len_mean', 'bwd_pkt_len_std', 'pkt_len_max',
    'pkt_len_min', 'pkt_len_mean', 'pkt_len_std', 'pkt_len_var',
    'fwd_header_len', 'bwd_header_len', 'fwd_seg_size_min',
    'fwd_act_data_pkts', 'flow_iat_mean', 'flow_iat_max', 'flow_iat_min',
    'flow_iat_std', 'fwd_iat_tot', 'fwd_iat_max', 'fwd_iat_min',
    'fwd_iat_mean', 'fwd_iat_std', 'bwd_iat_tot', 'bwd_iat_max',
    'bwd_iat_min', 'bwd_iat_mean', 'bwd_iat_std', 'fin_flag_cnt',
    'down_up_ratio', 'pkt_size_avg', 'init_fwd_win_byts',
    'init_bwd_win_byts', 'active_max', 'active_min', 'active_mean',
    'active_std', 'idle_max', 'idle_min', 'idle_mean', 'idle_std'
]

ATTACK_DATA_COLUMNS = ['src_ip', 'dst_ip',
                       'src_port', 'dst_port', 'protocol', 'timestamp']
server_process = None
cic_process = None
ATTACK_THRESHOLD = 0.2  # !! 0.3
ATTACK_THRESHOLD_FILE = 0.01  # !! 0.3


# scalar_power = PowerTransformer()
# scalar_minmax = MinMaxScaler()
# scalar_quantile = QuantileTransformer()

# NEW_MODEL_PATH = r"./models"
# above one was not working if we call python from another directory, like `python "C:\Users\Mohammad Arshad Ali\Desktop\Programming_not_dropbox\Programming\Kmit\project_school_2_2\zeroAttacks\main.py"`

NEW_MODEL_PATH = path.join(DIRNAME, "models")
SCALAR_PATH = path.join(DIRNAME, "scalars")


with open(path.join(SCALAR_PATH, "scalar_quantile.pkl"), "rb") as f:
    scalar_quantile = load(f)

with open(path.join(SCALAR_PATH, "scalar_min_max.pkl"), "rb") as f:
    scalar_minmax = load(f)

with open(path.join(SCALAR_PATH, "scalar_power.pkl"), "rb") as f:
    scalar_power = load(f)

#! cross site scripting model is not present.
attack_names = ['Bot',
                'Brute Force -XSS',
                # 'DDOS attack-HOIC',
                'DDOS attack-LOIC-UDP',
                'DDoS attacks-LOIC-HTTP',
                'DoS GoldenEye',
                # 'DoS Slowhttptest',
                'DoS slowloris',
                'DoS Hulk',
                # 'FTP-BruteForce',
                'Infilteration',
                'SSH-Bruteforce',
                'Web Attack - Brute Force']

# attack_names = ['botnet', 'brute_force', 'ddos', 'dos_goldeneye', 'dos_hulk', 'dos_slowhttptest',
#                 'dos_slowloris', 'ftp_patator', 'heartbleed', 'infiltration', 'portscan', 'sql_injection', 'ssh_patator', 'xss']

attack_files = ['Bot',
                'Brute Force -XSS',
                # 'DDOS attack-HOIC',
                'DDOS attack-LOIC-UDP',
                'DDoS attacks-LOIC-HTTP',
                'DoS GoldenEye',
                # 'DoS Slowhttptest',
                'DoS slowloris',
                'dos_hulk_min_max_n1_best',
                # 'FTP-BruteForce',
                'Infilteration',
                'SSH-Bruteforce',
                'Web Attack - Brute Force']

# attack_files = ['bot_data.csv', 'brute_force_data.csv', 'ddos.csv', 'dos_goldeneye_data.csv', 'dos_hulk_data.csv', 'dos_slowhttptest_data.csv', 'dos_slowloris_data.csv',
#                 'ftp_patator.csv', 'heartbleed_data.csv', 'infiltration_data.csv', 'portscan_data.csv', 'sql_injection_data.csv', 'ssh_patator.csv', 'xss_data.csv']

attack_models = {}


def warn(*args, **kwargs):
    pass


def load_model(model_name_to_save):
    with open((NEW_MODEL_PATH + rf"/{model_name_to_save}.pkl"), "rb") as f_model:
        return load(f_model)


def get_ip():
    try:
        s = socket_socket(socket_AF_INET, socket_SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        print("CONSOLE_LOG your ip: ", ip_address)
        return ip_address
    except:
        # TODO: use ipconfig, and active interface to get ip.
        return 'Unable to get IP'

prevNotificationMessage=None

def show_notification(message, title="Baboons- malicious attack detected"):
    global prevNotificationMessage

    if(prevNotificationMessage==message):
        return
    notification = Notification(
        app_id="Baboons",
        title=title,
        msg=message,
        duration="long",
        icon=path.join(DIRNAME, "assets/icon.png")
    )
    prevNotificationMessage=message
    # print(path.join(DIRNAME, "../src/assets/icon.png"))

    notification.show()


def block_ip(ip):
    # PowerShell command to check if the firewall rule exists
    check_command = f'Get-NetFirewallRule -DisplayName "Block Remote {ip}"'

    # Execute the check command to see if the rule already exists
    check_process = subprocess.Popen(
        ['powershell', '-Command', check_command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    check_stdout, check_stderr = check_process.communicate()

    if check_process.returncode == 0 and check_stdout.strip():
        # The firewall rule already exists
        print(f'Firewall rule for ip {ip} already exists. No action taken.')
    else:
        # The firewall rule does not exist, proceed to add it
        add_command = f'New-NetFirewallRule -RemoteAddress {ip} -DisplayName "Block Remote {ip}" -Direction inbound -Action Block'
        add_process = subprocess.Popen(
            ['powershell', '-Command', add_command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        add_stdout, add_stderr = add_process.communicate()

        if add_process.returncode == 0:
            print(f'CONSOLE_LOG ip {ip} blocked successfully on Windows.')
            show_notification(
                f"ip {ip} was blocked for malicious activity.", "Baboons- ip blocked")

            # saving blocked ip's in a json file as an array
            try:
                with open(path.join(DIRNAME, 'watchWarden_blocked_ips.json'), 'r') as f:
                    blocked_ips = load_json_file(f)

            except FileNotFoundError:
                blocked_ips = []

            blocked_ips.append(ip)

            with open(path.join(DIRNAME, 'watchWarden_blocked_ips.json'), 'w') as f:
                dump_json_file(blocked_ips, f)

        else:
            print('Error occurred while executing the command:')
            print(add_stderr.decode().strip())


def unblock_ip(ip):
    # PowerShell command to remove the firewall rule
    command = f'Remove-NetFirewallRule -DisplayName "Block Remote {ip}"'

    process = subprocess.Popen(
        ['powershell', '-Command', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if process.returncode == 0:
        print(f'CONSOLE_LOG ip {ip} unblocked successfully on Windows.')
        show_notification(f"ip {ip} was unblocked",
                          "Baboons- ip Unblocked")
        try:
            with open(path.join(DIRNAME, 'watchWarden_blocked_ips.json'), 'r') as f:
                blocked_ips = load_json_file(f)
                blocked_ips.remove(ip)

            with open(path.join(DIRNAME, 'watchWarden_blocked_ips.json'), 'w') as f:
                dump_json_file(blocked_ips, f)

        except FileNotFoundError:
            print("Trying to unblock an ip, but json file absent.")
    else:
        print('Error occurred while executing the command:')
        print(stderr.decode().strip())

# not using this function
# def runCicflowmeter(generate_false_attacks):
#     if generate_false_attacks:
#         command = r'cicflowmeter -i "Wi-Fi" -u "hello" -c "./CicFlowMeter_logData" --generate_false_attacks'
#     else:
#         command = r'cicflowmeter -i "Wi-Fi" -u "hello" -c "./CicFlowMeter_logData"'

#     process = Popen(command)  # !, stdout=DEVNULL
#     return process


def runCicflowmeter_from_function(input_interface, generate_false_attacks, save_logs):
    main_import(input_interface, generate_false_attacks=generate_false_attacks,
                save_logs=save_logs)  # * added/modified


for i in range(len(attack_names)):
    # ! removed .split(".")[0] from attack_files[i]
    attack_models[attack_names[i]] = load_model(attack_files[i])

warnings.warn = warn  # to supress sklearn warnings

MY_IP = get_ip()

loaded_model = load_model(LAYER1_MODEL)


# create a Socket.IO server instance
sio = socketio.Server(logger=False, engineio_logger=False)

# create a WSGI app instance
server_app = socketio.WSGIApp(sio)


def start_server(app=server_app):
    # Popen(['eventlet', 'wsgi', '--bind', 'localhost:8001', 'myapp:app'])
    eventlet.wsgi.server(eventlet.listen(('localhost', CONNECTION_PORT)), app)


# TODO: instead of looping over all rows, do prediction on whole dataset, and use descidsion function, or seujan confidence method to detect attack type
def detect_attack_type(minmax_transformed, power_transformed, attack_data=None, silent=False):
    detected_attacks = []
    attack_data_dict = attack_data.to_dict() if attack_data is not None else None

    for attack, model in attack_models.items():
        # print(np.array(input_attack))
        if attack == "DoS Hulk":
            # !!! this is the only model which is trained on minmax scalar
            if model.predict(minmax_transformed.reshape(1, -1)) == 1:
                detected_attacks.append(attack)

        else:
            if model.predict(power_transformed.reshape(1, -1)) == 1:
                detected_attacks.append(attack)

    attack_data_return=dumps_json(attack_data_dict) if attack_data is not None else None

    if len(detected_attacks) == 0:
        # !! in case of file analysis, these emits might cause problems.
        sio.emit("malicious", {"attackType": "Probable Zero day attack", "attackData": attack_data_return})
        print("MALICIOUS:",dumps_json({"attackType": "Probable Zero day attack", "attackData": attack_data_return}))

        if not silent:
            show_notification("Probable Zero day attack.")
        return "Probable Zero day attack."

    elif len(detected_attacks) == 1:
        sio.emit("malicious", {"attackType": detected_attacks[0], "attackData": attack_data_return})
        print("MALICIOUS:",dumps_json({"attackType": detected_attacks[0], "attackData": attack_data_return}))

        if not silent:
            show_notification(detected_attacks[0])
        return detected_attacks[0]

    else:
        sio.emit("malicious", {"attackType": choice(detected_attacks), "attackData": attack_data_return}) #!! change choice to a better method.. dependent on confidence
        print("MALICIOUS:",dumps_json({"attackType": choice(detected_attacks), "attackData": attack_data_return})) #!! change choice to a better method.. dependent on confidence

        if not silent:
            show_notification(choice(detected_attacks))
        return "Multiple possible attacks detected : " + ", ".join(detected_attacks)


def second_ml_layer(df, df_attack_data):
    # print(pred)

    # !NOTE: there might be some problems with the prediction, as if data is less then the scalars will not work properly, as fit_transform is used. So use a already fitted scalar on large collected cicflowmeter data, and ignore false positives by ignoring if very less rows of attacks are detected.
    try:
        df_power_transformed = scalar_power.transform(df)
    except Exception:
        # drop inf values
        df = df.replace([np.inf, -np.inf], 10**5)
        # df = df.fillna()
        df_power_transformed = scalar_power.transform(df)

    df_minmax_transformed = scalar_minmax.transform(df)

    # blocking ip
    extracted_src_ips = df_attack_data["src_ip"][df_attack_data["src_ip"] != MY_IP]
    counts = extracted_src_ips.value_counts()

    print("CONSOLE_LOG ips", df_attack_data["src_ip"].to_list())
    for i in counts.index:
        if counts[i] > counts.sum()*0.2:
            print("Blocking ip: ", i)
            block_ip(i)
        else:
            break

    for i in range(len(df)):

        # Self sending packets [False Positive]
        if df_attack_data.iloc[i].to_dict()["src_ip"] == MY_IP:
            # print("Attack from MY PC to MY PC")
            continue

        print("{}".format(detect_attack_type(
            df_minmax_transformed[i], df_power_transformed[i], df_attack_data.iloc[i])))
    print("\n\n")

# event handlers for Socket.IO server

# an event handler for the 'connect' event


@sio.event
def connect(sid, environ):
    print('Client connected:', sid)

# an event handler for the 'disconnect' event


@sio.event
def disconnect(sid):
    print('Client disconnected:', sid)


@sio.event
def electron(sid, data):
    if data == "stop":
        print(f" Log collection {data}")
        # server_process.terminate()
        # cic_process.terminate()
        # terminate_server_and_cicflowmeter() #!!
        # exit()
    return("stopped")

# an event handler for a custom event


@sio.event
def CicFlowMeter(sid, data):
    # print(f" CICFlowMeter : {data}")
    if len(data["data"][0]) != 0:
        # pred = loaded_model.predict(data["data"])
        df = DataFrame(**data)  # * added, data contains data and columns
        pred = loaded_model.predict(scalar_quantile.transform(
            df.loc[:, FIRST_LAYER_COLUMNS]))  # * added/modified

        # if pred.any() == False:

        #! to avoid false positives.
        print("CONSOLE_LOG", pred.sum()/len(pred))
        if pred.sum()/len(pred) < ATTACK_THRESHOLD:  # * added
            # print("     All Benign connections..\n\n") #!!
            pass
        else:
            pred_unique = np.unique(pred, return_counts=True)

            if len(pred_unique[0]) == 1:
                n_malicious = pred_unique[1][0]
            else:
                n_malicious = np.unique(pred, return_counts=True)[1][1]
            print("    : {} malicious logs detected.\n\n".format(n_malicious))
            # print(df.shape)
            # print(len([pred == 1][0]))
            # * added/modified
            second_ml_layer(
                (df.loc[[pred == 1][0], SECOND_LAYER_COLUMNS]), df.loc[[pred == 1][0], ATTACK_DATA_COLUMNS])
            # alert("{} malicious logs detected.".format(n_malicious))
    # alert(unique(loaded_model.predict(data["data"]), return_counts=True))


# start the server and cicflowmeter
def start_server_and_cicflowmeter(input_interface, generate_false_attacks, save_logs, minutes=None):
    # server=eventlet.wsgi.server(eventlet.listen(('localhost', 8001)), app)
    global server_process, cic_process

    server_process = Process(target=start_server)
    # start_server_and_cicflowmeter.server_process = server_process

    server_process.start()
    sleep(4)

    # process = runCicflowmeter(generate_false_attacks)
    cic_process = Process(target=runCicflowmeter_from_function,
                          args=(input_interface, generate_false_attacks, save_logs))  # * added/modified

    # start_server_and_cicflowmeter.process = process

    cic_process.start()

    # PROCESSES.extend([server_process, process])

    try:
        if minutes is not None:
            sleep(60*minutes)
            server_process.terminate()
            cic_process.terminate()

        else:  # running infinitely #!!!
            while True:
                pass

    except KeyboardInterrupt:
        server_process.terminate()
        cic_process.terminate()
        print("Server and Cicflowmeter terminated.")


# TODO: add confidence level to attack type.

def second_ml_layer_file(df, pred, path, df_scaled_minmax, df_scaled_power, silent=True):
    # print(pred)
    # df["attackType"] = [""]*df.shape[0]
    attacks = []

    for i in range(len(pred)):
        if pred[i] == 1:
            # print(df.values[i])
            attacks.append("{}".format(
                detect_attack_type(df_scaled_minmax[i], df_scaled_power[i], silent=silent)))  # * added/modified
        else:
            attacks.append("Benign")

    df["attackType"] = attacks
    analysed_path = path.rstrip(".csv")+"_analysed_WatchWarden.csv"
    df.to_csv(analysed_path, index=False)
    print(f"Analysed logs saved to: {analysed_path}")


def analyse_logs_from_file(path, silent=False):  # TODO:
    df = read_csv(path)
    df = (df.drop(columns=["label"])) if "label" in df.columns else (df)

    # pred = loaded_model.predict(df)
    pred = loaded_model.predict(scalar_quantile.transform(
        df.loc[:, FIRST_LAYER_COLUMNS]))  # * added/modified

    df_required_cols = df.loc[:, SECOND_LAYER_COLUMNS]

    try:
        df_scaled_power = scalar_power.transform(df_required_cols)
    except Exception:
        # drop inf values
        df_required_cols = df_required_cols.replace([np.inf, -np.inf], np.nan)
        df_required_cols = df_required_cols.fillna(method='ffill')
        # df = df.dropna()
        df_scaled_power = scalar_power.transform(df_required_cols)
    df_scaled_minmax = scalar_minmax.transform(df_required_cols)

    # if pred.any() == False:
    if pred.sum()/len(pred) < ATTACK_THRESHOLD_FILE:  # * added:
        print("All Benign connections..\n\n")
        pass
    else:
        pred_unique = np.unique(pred, return_counts=True)

        if len(pred_unique[0]) == 1:
            n_malicious = pred_unique[1][0]
        else:
            n_malicious = np.unique(pred, return_counts=True)[1][1]
        print("{} malicious logs detected, out of {}".format(
            n_malicious, pred.shape[0]))
        # alert("{} malicious logs detected, out of {}".format(n_malicious, pred.shape[0]))
        # second_ml_layer(df.values[pred == 1])
    second_ml_layer_file(df, pred, path, df_scaled_minmax,
                         df_scaled_power, silent=silent)  # * added/modified


def get_active_interface():
    connections = psutil.net_connections(kind='inet')
    for conn in connections:
        if conn.status == 'ESTABLISHED':
            local_ip = conn.laddr.ip
            for interface, addresses in psutil.net_if_addrs().items():
                if interface == 'Loopback Pseudo-Interface 1':
                    continue
                for address in addresses:
                    if address.address == local_ip:
                        print(f"Network interface detected: {interface}")
                        return interface

    print("No network interface detected.")
    return None

def getInterfacesList():
    connections = psutil.net_connections(kind='inet')

    active_interfaces = set()

    for conn in connections:
        if conn.status == 'ESTABLISHED':
            for interface, _ in psutil.net_if_addrs().items():
                active_interfaces.add(interface)
    return list(active_interfaces)

if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=False)

    # give an option that can recieve an optional argument

    group.add_argument(
        "-t",
        "--time",
        action="store",
        dest="time_limit",
        default=None,
        help="Give a time limit in minutes for Real time log collection and detection, default is None (infinite).",
    )
    group.add_argument(
        "-f",
        "--file",
        action="store",
        default=None,
        dest="file",
        help="Instead of real time log collection, Give a file path to analyse logs present in it.",
    )
    group.add_argument(
        "--unblock_ip",
        action="store",
        default=None,
        dest="unblock_ip",
        help="unblock the given ip address.",
    )

    parser.add_argument(
        "-g",
        "--generate_false_attacks",
        action="store_true",
        dest="generate_false_attacks",
        default=False,
        help="generate false attacks(for testing) during the real time detection. default is False.",
    )

    parser.add_argument(
        "-s",
        "--save_logs",
        action="store_true",
        dest="save_logs",
        default=False,
        help="save the collected logs.",
    )

    # parser.add_argument(
    #     "--silent",
    #     action="store_true",
    #     dest="silent",
    #     default=False,
    #     help="do not display notifications.",
    # )

    parser.add_argument(
        "-i",
        "--interface",
        action="store",
        dest="interface",
        default=None,
        help="Network interface to capture packets from. By default, the program will try to automatically detect the active network interface.",
    )

    args = parser.parse_args()

    if args.unblock_ip is not None:
        unblock_ip(args.unblock_ip)

    else:

        if args.file is None:

            if args.time_limit is None:
                MINUTES = None
            else:
                MINUTES = int(args.time_limit)

            if args.interface is None:
                interface = get_active_interface()
                if interface is None:
                    # print("Automatic detection of network interface failed. Please specify a network interface using -i or --interface.\n Example: python main.py -i \"Wi-Fi\"")
                    print("No network interface detected, please choose manually.")
                    # exit()
                    assert interface, "No network interface detected, please choose manually."
            
            else:
                interface = args.interface
                print("Using interface", interface)
                interfaces_list = getInterfacesList()

                if(args.interface not in interfaces_list):
                    print("Invalid Interface:", args.interface)
                    print("Valid Active Interfaces:")
                    for interface in interfaces_list:
                        print('\t' + interface)
                    print()
                    exit(1)
        
            start_server_and_cicflowmeter(
                interface, args.generate_false_attacks, args.save_logs, MINUTES,)  # TODO: add file location for saving logs

        else:
            analyse_logs_from_file(args.file, silent=True)
