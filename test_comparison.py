from wifi_scanner import get_connected_network, scan_wifi
from risk_engine import compare_connected_network


current = get_connected_network()

nearby = scan_wifi()


result = compare_connected_network(
    current,
    nearby
)


print("CONNECTED NETWORK CHECK")
print("----------------------------")


for line in result["comparison"]:

    print(line)