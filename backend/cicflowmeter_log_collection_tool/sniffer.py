import argparse

from scapy.sendrecv import AsyncSniffer

from .flow_session import generate_session_class
from time import ctime


def create_sniffer(
    input_file, input_interface, output_mode, output_file, url_model=None, generate_false_attacks=False, save_logs=False
):
    assert (input_file is None) ^ (input_interface is None)

    NewFlowSession = generate_session_class(
        output_mode, output_file, url_model, generate_false_attacks, save_logs)

    if input_file is not None:
        return AsyncSniffer(
            offline=input_file,
            filter="ip and (tcp or udp)",
            prn=None,
            session=NewFlowSession,
            store=False,
        )
    else:
        return AsyncSniffer(
            iface=input_interface,
            filter="ip and (tcp or udp)",
            prn=None,
            session=NewFlowSession,
            store=False,
        )


def main():
    parser = argparse.ArgumentParser()

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-i",
        "--interface",
        action="store",
        dest="input_interface",
        help="capture online data from INPUT_INTERFACE",
    )

    input_group.add_argument(
        "-f",
        "--file",
        action="store",
        dest="input_file",
        help="capture offline data from INPUT_FILE",
    )

    output_group = parser.add_mutually_exclusive_group(required=False)
    output_group.add_argument(
        "-c",
        "--csv",
        "--flow",
        action="store_const",
        const="flow",
        dest="output_mode",
        help="output flows as csv",
    )

    url_model = parser.add_mutually_exclusive_group(required=False)
    url_model.add_argument(
        "-u",
        "--url",
        action="store",
        dest="url_model",
        help="URL endpoint for send to Machine Learning Model. e.g http://0.0.0.0:80/prediction",
    )

    parser.add_argument(
        "output",
        help="output file name (in flow mode) or directory (in sequence mode)",
    )

    # * added
    parser.add_argument(
        "-g",
        "--generate_false_attacks",
        action="store_true",
        dest="generate_false_attacks",
        default=False,
        help="Choose whether to generate false attacks(for testing) or not.",
    )
    parser.add_argument(
        "-s",
        "--save_logs",
        action="store_true",
        dest="save_logs",
        default=False,
        help="Choose whether to save the collected logs or not.",
    )
    # * added

    args = parser.parse_args()

    sniffer = create_sniffer(
        args.input_file,
        args.input_interface,
        args.output_mode,
        args.output,
        args.url_model,
        args.generate_false_attacks,
        args.save_logs,
    )
    sniffer.start()

    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        sniffer.join()


def main_import(input_interface, output=None, generate_false_attacks=False, save_logs=False, url_model=None, output_mode="flow", input_file=None):  # ! set url_model to none

    # for saving logs
    output = f"WatchWarden_logs_{ctime()}.csv"  # * added

    sniffer = create_sniffer(
        input_file,
        input_interface,
        output_mode,
        output,
        url_model,
        generate_false_attacks,
        save_logs
    )
    sniffer.start()

    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        sniffer.join()


if __name__ == "__main__":
    main()
