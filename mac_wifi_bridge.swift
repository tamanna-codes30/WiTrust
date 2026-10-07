import CoreWLAN
import Foundation
import CoreLocation
import AppKit

func requestLocationPermission() {
    let locationManager = CLLocationManager()
    guard locationManager.authorizationStatus == .notDetermined else { return }

    locationManager.requestWhenInUseAuthorization()
    let deadline = Date().addingTimeInterval(60)
    while locationManager.authorizationStatus == .notDetermined && Date() < deadline {
        RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.25))
    }
}

func securityName(_ network: CWNetwork) -> String {
    if network.supportsSecurity(.wpa3Personal) || network.supportsSecurity(.wpa3Enterprise) {
        return "WPA3"
    }
    if network.supportsSecurity(.wpa3Transition) {
        return "WPA3/WPA2 Personal"
    }
    if network.supportsSecurity(.wpa2Personal) || network.supportsSecurity(.wpa2Enterprise) {
        return "WPA2"
    }
    if network.supportsSecurity(.wpaPersonal) || network.supportsSecurity(.wpaEnterprise) {
        return "WPA"
    }
    if network.supportsSecurity(.WEP) || network.supportsSecurity(.dynamicWEP) {
        return "WEP"
    }
    if network.supportsSecurity(.none) {
        return "Open"
    }
    return "Unknown"
}

func bandName(_ channel: CWChannel?) -> String {
    guard let channel = channel else { return "" }
    switch channel.channelBand {
    case .band2GHz:
        return "2.4 GHz"
    case .band5GHz:
        return "5 GHz"
    case .band6GHz:
        return "6 GHz"
    default:
        return ""
    }
}

func networkRecord(_ network: CWNetwork) -> [String: Any] {
    let channelInfo = network.wlanChannel
    let channel = channelInfo?.channelNumber ?? 0
    let band = bandName(channelInfo)
    let security = securityName(network)
    let ssid = network.ssid
    let bssid = network.bssid
    return [
        "ssid": ssid ?? "",
        "bssid": bssid ?? "",
        "ssid_redacted": ssid == nil,
        "signal": "\(network.rssiValue) dBm",
        "authentication": security,
        "encryption": security == "Open" ? "None" : (security == "Unknown" ? "" : "Encrypted"),
        "channel": channel == 0 ? "" : String(channel),
        "band": band
    ]
}

func connectedRecord(_ interface: CWInterface) -> [String: Any] {
    let channelInfo = interface.wlanChannel()
    let channel = channelInfo?.channelNumber ?? 0
    let band = bandName(channelInfo)
    let ssid = interface.ssid()
    let bssid = interface.bssid()
    let signal = interface.rssiValue()
    let connected = ssid != nil || bssid != nil || signal != 0 || channelInfo != nil
    let security: String
    switch interface.security() {
    case .wpa3Personal, .wpa3Enterprise:
        security = "WPA3"
    case .wpa3Transition:
        security = "WPA3/WPA2 Personal"
    case .wpa2Personal, .wpa2Enterprise:
        security = "WPA2"
    case .wpaPersonal, .wpaEnterprise:
        security = "WPA"
    case .WEP, .dynamicWEP:
        security = "WEP"
    case .none:
        security = "Open"
    default:
        security = "Unknown"
    }
    return [
        "ssid": ssid ?? "",
        "bssid": bssid ?? "",
        "connected": connected,
        "ssid_redacted": connected && ssid == nil,
        "signal": signal == 0 ? "" : "\(signal) dBm",
        "authentication": security,
        "encryption": security == "Open" ? "None" : (security == "Unknown" ? "" : "Encrypted"),
        "channel": channel == 0 ? "" : String(channel),
        "band": band
    ]
}

let arguments = Array(CommandLine.arguments.dropFirst())

do {
    let application = NSApplication.shared
    application.setActivationPolicy(.accessory)
    application.activate(ignoringOtherApps: true)

    requestLocationPermission()

    guard let interface = CWWiFiClient.shared().interface() else {
        throw NSError(domain: "WiTrust", code: 1, userInfo: [NSLocalizedDescriptionKey: "No Wi-Fi interface is available."])
    }

    let output: Any
    if arguments.first == "connected" {
        output = connectedRecord(interface)
    } else {
        let networks = try interface.scanForNetworks(withSSID: nil, includeHidden: false)
        output = networks.map(networkRecord).sorted {
            String(describing: $0["ssid"] ?? "").localizedCaseInsensitiveCompare(
                String(describing: $1["ssid"] ?? "")
            ) == .orderedAscending
        }
    }

    let data = try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
    if arguments.count >= 2 {
        try data.write(to: URL(fileURLWithPath: arguments[1]), options: .atomic)
    } else {
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([0x0A]))
    }
} catch {
    let message = "Wi-Fi scan failed: \(error.localizedDescription)"
    if arguments.count >= 3 {
        try? Data(message.utf8).write(to: URL(fileURLWithPath: arguments[2]), options: .atomic)
    }
    FileHandle.standardError.write(Data("\(message)\n".utf8))
    exit(1)
}
