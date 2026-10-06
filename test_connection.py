from wifi_scanner import get_connected_network

network = get_connected_network()

print("CURRENT NETWORK")
print("--------------------")
print("SSID:", network["ssid"])
print("Security:", network["authentication"])
print("Encryption:", network["encryption"])
print("Signal:", network["signal"])
print("Band:", network["band"])
print("Channel:", network["channel"])