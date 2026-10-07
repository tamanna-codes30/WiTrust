"""Manual live comparison check; does not run during test discovery."""

from risk_engine import compare_connected_network
from wifi_scanner import get_connected_network, scan_wifi


def main():
    current_network = get_connected_network()
    nearby_networks = scan_wifi()
    result = compare_connected_network(current_network, nearby_networks)

    print("CONNECTED NETWORK CHECK")
    print("----------------------------")
    for line in result["comparison"]:
        print(line)


if __name__ == "__main__":
    main()
