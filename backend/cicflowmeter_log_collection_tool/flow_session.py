import csv
from collections import defaultdict

import requests
from scapy.sessions import DefaultSession

from .features.context.packet_direction import PacketDirection
from .features.context.packet_flow_key import get_packet_flow_key
from .flow import Flow

# from time import time as time_time #* added
from .features.send_to_server import Client  # * added
from .constants import CONNECTION_PORT  # * added

EXPIRED_UPDATE = 4
# EXPIRED_UPDATE = 10  # !!!
MACHINE_LEARNING_API = "http://localhost:8000/predict"
# GARBAGE_COLLECT_PACKETS = 100
GARBAGE_COLLECT_PACKETS = 10


class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, *args, **kwargs):

        # * added
        print("Cicflowmeter initialised..")
        #!!!!!!!
        try:
            self.connection_to_server = Client(CONNECTION_PORT)
        except Exception as e:
            # print(e)
            print("\n\nServer not running\n\n")
            raise e
        # * added

        self.flows = {}
        self.csv_line = 0

        if self.save_logs:  # * added
            if self.output_mode == "flow":
                output = open(self.output_file.replace(":", "_"), "w")
                self.csv_writer = csv.writer(output)

        self.packets_count = 0

        self.clumped_flows_per_label = defaultdict(list)

        super(FlowSession, self).__init__(*args, **kwargs)

    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer
        self.garbage_collect(None)
        return super(FlowSession, self).toPacketList()

    def on_packet_received(self, packet):
        count = 0
        direction = PacketDirection.FORWARD

        if self.output_mode != "flow":
            if "TCP" not in packet:
                return
            elif "UDP" not in packet:
                return

        try:
            # Creates a key variable to check
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))
        except Exception:
            return

        self.packets_count += 1

        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))

            if flow is None:
                # If no flow exists create a new flow
                direction = PacketDirection.FORWARD
                flow = Flow(packet, direction)
                packet_flow_key = get_packet_flow_key(packet, direction)
                self.flows[(packet_flow_key, count)] = flow

            elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
                # If the packet exists in the flow but the packet is sent
                # after too much of a delay than it is a part of a new flow.
                expired = EXPIRED_UPDATE
                while (packet.time - flow.latest_timestamp) > expired:
                    count += 1
                    expired += EXPIRED_UPDATE
                    flow = self.flows.get((packet_flow_key, count))

                    if flow is None:
                        flow = Flow(packet, direction)
                        self.flows[(packet_flow_key, count)] = flow
                        break

        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            expired = EXPIRED_UPDATE
            while (packet.time - flow.latest_timestamp) > expired:

                count += 1
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    flow = Flow(packet, direction)
                    self.flows[(packet_flow_key, count)] = flow
                    break

        flow.add_packet(packet, direction)
        if self.packets_count % 300 == 0: #*packets to be printed at an interval of
            print("packets collected :", self.packets_count)  # * added
        #!!!

        GARBAGE_COLLECT_PACKETS = 100  # * added
        #! without, this UnboundLocalError: local variable 'GARBAGE_COLLECT_PACKETS' referenced before assignment

        if not self.url_model:
            GARBAGE_COLLECT_PACKETS = 1000
            # GARBAGE_COLLECT_PACKETS = 100  # !!!

        if self.packets_count % GARBAGE_COLLECT_PACKETS == 0 or (
            flow.duration > 120 and self.output_mode == "flow"
        ):
            self.garbage_collect(packet.time)

    def get_flows(self) -> list:
        return self.flows.values()

    def garbage_collect(self, latest_time) -> None:
        # TODO: Garbage Collection / Feature Extraction should have a separate thread
        if not self.url_model:
            print("Log Collection Began. Flows = {}".format(len(self.flows)))
        keys = list(self.flows.keys())

        # TODO: fix columns
        data_for_server = {"data": [],
                           "columns": ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'timestamp', 'flow_duration', 'flow_byts_s', 'flow_pkts_s', 'fwd_pkts_s',
                                       'bwd_pkts_s', 'tot_fwd_pkts', 'tot_bwd_pkts', 'totlen_fwd_pkts', 'totlen_bwd_pkts', 'fwd_pkt_len_max', 'fwd_pkt_len_min', 'fwd_pkt_len_mean', 'fwd_pkt_len_std',
                                       'bwd_pkt_len_max', 'bwd_pkt_len_min', 'bwd_pkt_len_mean', 'bwd_pkt_len_std', 'pkt_len_max', 'pkt_len_min', 'pkt_len_mean', 'pkt_len_std', 'pkt_len_var',
                                       'fwd_header_len', 'bwd_header_len', 'fwd_seg_size_min', 'fwd_act_data_pkts', 'flow_iat_mean', 'flow_iat_max', 'flow_iat_min', 'flow_iat_std', 'fwd_iat_tot',
                                       'fwd_iat_max', 'fwd_iat_min', 'fwd_iat_mean', 'fwd_iat_std', 'bwd_iat_tot', 'bwd_iat_max', 'bwd_iat_min', 'bwd_iat_mean',
                                       'bwd_iat_std', 'fin_flag_cnt', 'psh_flag_cnt', 'ack_flag_cnt', 'down_up_ratio', 'pkt_size_avg', 'init_fwd_win_byts', 'init_bwd_win_byts', 'active_max',
                                       'active_min', 'active_mean', 'active_std', 'idle_max', 'idle_min', 'idle_mean', 'idle_std']}
        for k in keys:
            flow = self.flows.get(k)

            if (
                latest_time is None
                or latest_time - flow.latest_timestamp > EXPIRED_UPDATE
                or flow.duration > 90
            ):
                data = flow.get_data()

                # POST Request to Model API
                if self.url_model:
                    payload = {
                        "columns": list(data.keys()),
                        "data": [list(data.values())],
                    }
                    post = requests.post(
                        self.url_model,
                        json=payload,
                        headers={
                            "Content-Type": "application/json; format=pandas-split"
                        },
                    )
                    resp = post.json()
                    result = resp["result"].pop()
                    if result == 0:
                        result_print = "Benign"
                    else:
                        result_print = "Malicious"

                    print(
                        "{: <15}:{: <6} -> {: <15}:{: <6} \t {} (~{:.2f}%)".format(
                            resp["src_ip"],
                            resp["src_port"],
                            resp["dst_ip"],
                            resp["dst_port"],
                            result_print,
                            resp["probability"].pop()[result] * 100,
                        )
                    )

                # * added/modified
                data_for_server['data'].append(list(data.values()))

                if self.save_logs:
                    if self.csv_line == 0:
                        self.csv_writer.writerow(data.keys())

                    self.csv_writer.writerow(data.values())
                    self.csv_line += 1

                # * added/modified

                del self.flows[k]

        self.connection_to_server.sendToServer(
            "CicFlowMeter", data_for_server, self.generate_false_attacks)

        if not self.url_model:
            print("Log Collection Finished. Flows = {}".format(len(self.flows)))


def generate_session_class(output_mode, output_file, url_model, generate_false_attacks, save_logs):
    return type(
        "NewFlowSession",
        (FlowSession,),
        {
            "output_mode": output_mode,
            "output_file": output_file,
            "url_model": url_model,
            "generate_false_attacks": generate_false_attacks,  # * added
            "save_logs": save_logs  # * added
        },
    )
