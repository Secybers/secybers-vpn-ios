import NetworkExtension
import Foundation

class PacketTunnelProvider: NEPacketTunnelProvider {
    private var wgHandle: Int32 = -1

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard
            let protocolConfiguration = protocolConfiguration as? NETunnelProviderProtocol,
            let providerConfiguration = protocolConfiguration.providerConfiguration,
            let privateKeyB64 = providerConfiguration["privateKey"] as? String,
            let serverPublicKeyB64 = providerConfiguration["serverPublicKey"] as? String,
            let assignedIp = providerConfiguration["assignedIp"] as? String,
            let endpoint = providerConfiguration["endpoint"] as? String
        else {
            completionHandler(NSError(domain: "WG", code: 1, userInfo: [NSLocalizedDescriptionKey: "Missing WireGuard configuration."]))
            return
        }

        let dns = providerConfiguration["dns"] as? String ?? "1.1.1.1"
        let tunnelAddress = assignedIp.components(separatedBy: "/").first ?? assignedIp
        let serverHost = endpoint.components(separatedBy: ":").first ?? endpoint

        guard let privateKeyData = Data(base64Encoded: privateKeyB64),
              let serverPublicKeyData = Data(base64Encoded: serverPublicKeyB64) else {
            completionHandler(NSError(domain: "WG", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid key format."]))
            return
        }

        let wgConfig = "private_key=\(privateKeyData.hexString)\npublic_key=\(serverPublicKeyData.hexString)\nendpoint=\(endpoint)\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n\n"

        let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: serverHost)
        let ipv4Settings = NEIPv4Settings(addresses: [tunnelAddress], subnetMasks: ["255.255.255.0"])
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        // All traffic routes through the WireGuard tunnel.
        // Production builds bypass backend API traffic from the tunnel via excludedRoutes.
        // That logic is intentionally omitted from this open-source layer.
        networkSettings.ipv4Settings = ipv4Settings
        let dnsSettings = NEDNSSettings(servers: [dns])
        dnsSettings.matchDomains = [""]
        networkSettings.dnsSettings = dnsSettings
        networkSettings.mtu = 1420

        setTunnelNetworkSettings(networkSettings) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                NSLog("[WG] setTunnelNetworkSettings error: %{public}@", error.localizedDescription)
                completionHandler(error)
                return
            }

            var tunFd: Int32 = -1

            // Get the highest numbered utun (the most recently created = ours)
            var highestUtunNum = -1
            for fd in 0..<1024 {
                var buf = [CChar](repeating: 0, count: Int(IFNAMSIZ))
                var len = socklen_t(IFNAMSIZ)
                if getsockopt(Int32(fd), 2, 2, &buf, &len) == 0 {
                    let name = String(cString: buf)
                    if name.hasPrefix("utun") {
                        let numStr = String(name.dropFirst(4))
                        let num = Int(numStr) ?? -1
                        if num > highestUtunNum {
                            highestUtunNum = num
                            tunFd = Int32(fd)
                            NSLog("[WG] Found utun candidate: %{public}@ fd=%{public}d", name, fd)
                        }
                    }
                }
            }
            NSLog("[WG] Selected tunFd: %d (utun%{public}d)", tunFd, highestUtunNum)

            guard tunFd >= 0 else {
                completionHandler(NSError(domain: "WG", code: 3, userInfo: [NSLocalizedDescriptionKey: "Could not get tunnel file descriptor."]))
                return
            }


            NSLog("[WG] tunFd before wgTurnOn: %{public}d", tunFd)
            self.wgHandle = wgTurnOn(wgConfig, tunFd)
            NSLog("[WG] wgTurnOn result handle: %{public}d", self.wgHandle)

            if self.wgHandle < 0 {
                let msg = "wgTurnOn failed with handle: \(self.wgHandle)"
                NSLog("[WG] FAILED: %{public}@", msg)
                completionHandler(NSError(domain: "WG", code: 4, userInfo: [NSLocalizedDescriptionKey: msg]))
                return
            }
            NSLog("[WG] SUCCESS: tunnel is up")

            wgDisableSomeRoamingForBrokenMobileSemantics(self.wgHandle)
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        if wgHandle >= 0 {
            wgTurnOff(wgHandle)
            wgHandle = -1
        }
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        completionHandler?(messageData)
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func wake() {
        if wgHandle >= 0 { wgBumpSockets(wgHandle) }
    }
}

extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
