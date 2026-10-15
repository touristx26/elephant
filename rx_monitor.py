#!/usr/bin/env python3

import socket
import json
import time
import re
import csv
from datetime import datetime


# =========================
# Configuration
# =========================

SOCKET_PATH = "/var/run/dpdk/rte/dpdk_telemetry.v2"

PORT_ID = 0

# Sampling interval
INTERVAL = 1.0

# CSV output
CSV_FILE = "rx_queue_stats.csv"

# Telemetry buffer
BUF_LEN = 16384


# =========================
# DPDK Telemetry V2
# =========================

class DPDKTelemetry:

    def __init__(self, socket_path):
        self.socket_path = socket_path
        self.sock = None
        self.output_buf_len = BUF_LEN

    def connect(self):

        self.sock = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_SEQPACKET
        )

        self.sock.connect(self.socket_path)

        # First packet from DPDK:
        # {
        #   "version": "DPDK 21.11.9",
        #   "pid": 50390,
        #   "max_output_len": 16384
        # }
        reply = self.sock.recv(1024).decode()

        hello = json.loads(reply)

        self.output_buf_len = hello["max_output_len"]

        print("Telemetry:", reply)

        # Get command list, same as official dpdk-telemetry.py
        self.sock.send(b"/")

        reply = self.sock.recv(self.output_buf_len).decode()

        self.commands = json.loads(reply)["/"]

        print("Connected to DPDK Telemetry")
        print("Socket :", self.socket_path)
        print()

    def command(self, command):

        # IMPORTANT:
        # DPDK 21.11 telemetry v2 expects
        # the command itself, NOT a JSON request.
        self.sock.send(command.encode())

        reply = self.sock.recv(self.output_buf_len).decode()

        try:
            return json.loads(reply)

        except json.JSONDecodeError:
            print("Telemetry returned invalid JSON:")
            print(reply)
            raise

    def close(self):

        if self.sock is not None:
            self.sock.close()
            self.sock = None


# =========================
# XStats
# =========================

def get_xstats(telemetry):

    result = telemetry.command(
        f"/ethdev/xstats,{PORT_ID}"
    )

    return result["/ethdev/xstats"]


# =========================
# Detect RX queues
# =========================

def get_rx_queues(stats):

    queues = []

    pattern = re.compile(
        r"^rx_q(\d+)_packets$"
    )

    for key in stats.keys():

        match = pattern.match(key)

        if match:
            queues.append(
                int(match.group(1))
            )

    return sorted(set(queues))


# =========================
# Main
# =========================

def main():

    telemetry = DPDKTelemetry(
        SOCKET_PATH
    )

    csv_file = None

    try:

        # -------------------------
        # Connect
        # -------------------------

        telemetry.connect()

        # -------------------------
        # First statistics
        # -------------------------

        stats = get_xstats(
            telemetry
        )

        queues = get_rx_queues(
            stats
        )

        if not queues:

            print(
                "ERROR: No RX queues found."
            )

            return

        print(
            "Detected RX queues:",
            queues
        )

        print()

        # -------------------------
        # CSV
        # -------------------------

        csv_file = open(
            CSV_FILE,
            "w",
            newline="",
            buffering=1
        )

        writer = csv.writer(
            csv_file
        )

        header = [
            "timestamp"
        ]

        for q in queues:

            header.extend([
                f"rx_q{q}_pps",
                f"rx_q{q}_mbps",
                f"rx_q{q}_packets",
                f"rx_q{q}_bytes",
                f"rx_q{q}_errors",
                f"rxq{q}_empty_pmd",
                f"rxq{q}_rx_nombuf_pmd",
            ])

        writer.writerow(header)

        # -------------------------
        # Previous counters
        # -------------------------

        previous = {}

        for q in queues:

            previous[q] = {
                "packets": stats.get(
                    f"rx_q{q}_packets",
                    0
                ),

                "bytes": stats.get(
                    f"rx_q{q}_bytes",
                    0
                ),

                "errors": stats.get(
                    f"rx_q{q}_errors",
                    0
                ),

                "empty": stats.get(
                    f"rxq{q}_empty_pmd",
                    0
                ),

                "nombuf": stats.get(
                    f"rxq{q}_rx_nombuf_pmd",
                    0
                ),
            }

        previous_time = time.monotonic()

        # -------------------------
        # Sampling loop
        # -------------------------

        while True:

            time.sleep(INTERVAL)

            stats = get_xstats(
                telemetry
            )

            now = time.monotonic()

            elapsed = (
                now - previous_time
            )

            timestamp = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            row = [
                timestamp
            ]

            print(
                f"\n[{timestamp}] "
                f"interval={elapsed:.3f}s"
            )

            # -------------------------
            # Each RX queue
            # -------------------------

            for q in queues:

                packets = stats.get(
                    f"rx_q{q}_packets",
                    0
                )

                bytes_ = stats.get(
                    f"rx_q{q}_bytes",
                    0
                )

                errors = stats.get(
                    f"rx_q{q}_errors",
                    0
                )

                empty = stats.get(
                    f"rxq{q}_empty_pmd",
                    0
                )

                nombuf = stats.get(
                    f"rxq{q}_rx_nombuf_pmd",
                    0
                )

                # -------------------------
                # Delta
                # -------------------------

                packet_delta = (
                    packets
                    - previous[q]["packets"]
                )

                byte_delta = (
                    bytes_
                    - previous[q]["bytes"]
                )

                # Counter reset / wrap
                if packet_delta < 0:
                    packet_delta = 0

                if byte_delta < 0:
                    byte_delta = 0

                # -------------------------
                # PPS
                # -------------------------

                pps = (
                    packet_delta
                    / elapsed
                )

                # -------------------------
                # Mbps
                # -------------------------

                mbps = (
                    byte_delta
                    * 8
                    / elapsed
                    / 1_000_000
                )

                # -------------------------
                # Print
                # -------------------------

                print(
                    f"  RXQ{q}: "
                    f"{pps:12,.0f} PPS  "
                    f"{mbps:10.2f} Mbps  "
                    f"packets={packets:,}  "
                    f"errors={errors}"
                )

                # -------------------------
                # CSV
                # -------------------------

                row.extend([
                    f"{pps:.2f}",
                    f"{mbps:.2f}",
                    packets,
                    bytes_,
                    errors,
                    empty,
                    nombuf,
                ])

                # -------------------------
                # Update previous
                # -------------------------

                previous[q]["packets"] = packets
                previous[q]["bytes"] = bytes_
                previous[q]["errors"] = errors
                previous[q]["empty"] = empty
                previous[q]["nombuf"] = nombuf

            writer.writerow(row)

            previous_time = now

    except KeyboardInterrupt:

        print()
        print("Stopping...")

    except Exception as e:

        print()
        print("ERROR:")
        print(e)

        raise

    finally:

        if csv_file is not None:
            csv_file.close()

        telemetry.close()


if __name__ == "__main__":
    main()