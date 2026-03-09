import NetworkExtension
import CryptoKit
import Foundation

public class Connection: NSObject, ObservableObject {
    private var providerManager: NETunnelProviderManager! = nil
    private var appGroupDefaults: UserDefaults
    private var profile: Profile

    @Published var connectionStatus = NEVPNStatus.disconnected
    @Published var output = [Log]()
    @Published var message = Message("", .message)

    public init(profile: Profile) {
        appGroupDefaults = UserDefaults(suiteName: Config.appGroupName)!
        self.profile = profile
        super.init()
        appGroupDefaults.removeObject(forKey: Log.LOG_KEY)
        appGroupDefaults.addObserver(self, forKeyPath: Log.LOG_KEY, options: .new, context: nil)
        Log.append(Util.localize("application-started", Util.getAppName()), .debug, .mainApp)
        loadProviderManager {
            self.connectionStatus = self.providerManager.connection.status
            self.message = self.providerManager.connection.status == NEVPNStatus.invalid ||
                self.providerManager.connection.status == NEVPNStatus.disconnected
                ? Message(Util.localize("welcome"), .message)
                : self.NEVPNStatusToMessage(self.providerManager.connection.status)
            NotificationCenter.default.addObserver(
                forName: NSNotification.Name.NEVPNStatusDidChange,
                object: self.providerManager.connection,
                queue: OperationQueue.main
            ) { _ in
                let newStatus = self.providerManager.connection.status
                guard newStatus != self.connectionStatus else { return }
                self.connectionStatus = newStatus
                Log.append(Util.localize("connection-status-changed", newStatus.description), .info, .mainApp)
                self.message = self.NEVPNStatusToMessage(newStatus)
                NotificationCenter.default.post(
                    name: NSNotification.Name("VPNStatusChanged"),
                    object: nil,
                    userInfo: ["status": self.providerManager.connection.status, "server": self.profile.serverIpAddress ?? ""]
                )
            }
        }
    }

    private func loadProviderManager(completion: @escaping () -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { (managers, error) in
            if error == nil {
                self.providerManager = self.providerManager ?? managers?.first ?? NETunnelProviderManager()
                completion()
            } else {
                Log.append("\(error.debugDescription)", .error, .mainApp)
                self.message = Message(Util.localize("error-adding-vpn-configuration"), .error)
            }
        }
    }

    private func NEVPNStatusToMessage(_ status: NEVPNStatus) -> Message {
        switch status {
        case .disconnected: return Message(status.message, .message)
        case .invalid: return Message(status.message, .error)
        case .connected: return Message(status.message, .success)
        case .connecting: return Message(status.message, .message)
        case .disconnecting: return Message(status.message, .message)
        case .reasserting: return Message(status.message, .message)
        @unknown default: return Message(status.message, .error)
        }
    }

    public override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey: Any]?, context: UnsafeMutableRawPointer?) {
        if keyPath == Log.LOG_KEY {
            let newEntry = change?[NSKeyValueChangeKey.newKey] as? [Data] ?? [Data]()
            updateLog(logData: newEntry)
        }
    }

    private func updateLog(logData: [Data]) {
        let qtNewMessages = logData.count - output.count
        if qtNewMessages > 0 {
            let newMessages = logData[logData.count - qtNewMessages ..< logData.count]
            newMessages.forEach { message in
                let log = Log.getValue(data: message)
                output.append(log)
                NSLog(log.text)
            }
        }
    }

    private func getOrCreatePrivateKey() -> Curve25519.KeyAgreement.PrivateKey {
        let keychainKey = "com.secybers.wg.privateKey"
        if let b64 = KeychainHelper.shared.read(forKey: keychainKey),
           let data = Data(base64Encoded: b64),
           let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data) {
            return key
        }
        let newKey = Curve25519.KeyAgreement.PrivateKey()
        KeychainHelper.shared.save(newKey.rawRepresentation.base64EncodedString(), forKey: keychainKey)
        return newKey
    }

    struct PeerInfo {
        let assignedIp: String
        let serverPublicKey: String
        let endpoint: String
    }

    private func registerPeer(clientPublicKey: String, completion: @escaping (Result<PeerInfo, Error>) -> Void) {
        guard let url = URL(string: "https://app.secybers.com/secyber/api/v1.0/vpn/register-peer") else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        NSLog("DEBUG [WG] registerPeer serverId=\(profile.serverId ?? "NIL") publicKey=\(clientPublicKey)")
        let body: [String: Any] = ["ServerId": profile.serverId ?? "", "ClientPublicKey": clientPublicKey]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)
        URLSession.shared.dataTask(with: request) { data, _, error in
            if let error = error { completion(.failure(error)); return }
            NSLog("DEBUG [WG] response data: %@", String(data: data ?? Data(), encoding: .utf8) ?? "nil")
            guard let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  
                  let peerData = json["data"] as? [String: Any],
                  let assignedIp = peerData["assignedIp"] as? String,
                  let serverPublicKey = peerData["serverPublicKey"] as? String,
                  let endpoint = peerData["endpoint"] as? String else {
                completion(.failure(NSError(domain: "WG", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid peer response"])))
                return
            }
            completion(.success(PeerInfo(assignedIp: assignedIp, serverPublicKey: serverPublicKey, endpoint: endpoint)))
        }.resume()
    }

    public func configureAndSave(completion: @escaping (Error?) -> Void) {
        let privateKey = getOrCreatePrivateKey()
        let publicKeyBase64 = privateKey.publicKey.rawRepresentation.base64EncodedString()
        registerPeer(clientPublicKey: publicKeyBase64) { result in
            switch result {
            case .failure(let error):
                completion(error)
            case .success(let peerInfo):
                let tunnelProtocol = NETunnelProviderProtocol()
                tunnelProtocol.providerBundleIdentifier = "com.secybers.secybers-vpn.TunnelProvider"
                tunnelProtocol.serverAddress = self.profile.serverIpAddress
                tunnelProtocol.providerConfiguration = [
                    "privateKey": privateKey.rawRepresentation.base64EncodedString(),
                    "serverPublicKey": peerInfo.serverPublicKey,
                    "assignedIp": peerInfo.assignedIp,
                    "endpoint": peerInfo.endpoint,
                    "dns": "1.1.1.1"
                ]
                tunnelProtocol.disconnectOnSleep = false
                self.providerManager.protocolConfiguration = tunnelProtocol
                self.providerManager.localizedDescription = "Secybers VPN"
                self.providerManager.isEnabled = true
                self.providerManager.saveToPreferences { error in
                    if error == nil {
                        self.providerManager.loadFromPreferences { _ in completion(nil) }
                    } else {
                        completion(error)
                    }
                }
            }
        }
    }

    public func startVPN() {
        if self.providerManager == nil {
            loadProviderManager { self.configureAndSave { _ in self.startTunnel() } }
        } else {
            self.configureAndSave { _ in self.startTunnel() }
        }
    }

    private func startTunnel() {
        do {
            try self.providerManager.connection.startVPNTunnel()
        } catch {
            Log.append(error.localizedDescription, .error, .mainApp)
        }
    }

    public func stopVPN() {
        self.providerManager.connection.stopVPNTunnel()
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
            self.removePeer()
        }
    }

    private func removePeer() {
        guard let serverId = profile.serverId,
              let b64 = KeychainHelper.shared.read(forKey: "com.secybers.wg.privateKey"),
              let data = Data(base64Encoded: b64),
              let privateKey = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data) else { return }
        let publicKeyBase64 = privateKey.publicKey.rawRepresentation.base64EncodedString()
        guard let url = URL(string: "https://app.secybers.com/secyber/api/v1.0/vpn/remove-peer") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: ["ServerId": serverId, "ClientPublicKey": publicKeyBase64])
        URLSession.shared.dataTask(with: req) { _, _, _ in }.resume()
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
        appGroupDefaults.removeObserver(self, forKeyPath: Log.LOG_KEY)
    }
}

extension NEVPNStatus: CustomStringConvertible {
    public var description: String {
        switch self {
        case .disconnected: return "Disconnected"
        case .invalid: return "Invalid"
        case .connected: return "Connected"
        case .connecting: return "Connecting"
        case .disconnecting: return "Disconnecting"
        case .reasserting: return "Reasserting"
        @unknown default: return "unknown"
        }
    }
    public var message: String {
        switch self {
        case .disconnected: return Util.localize("Disconnected")
        case .invalid: return Util.localize("Invalid")
        case .connected: return Util.localize("Connected")
        case .connecting: return Util.localize("Connecting")
        case .disconnecting: return Util.localize("Disconnecting")
        case .reasserting: return Util.localize("Reconnecting")
        @unknown default: return "unknown"
        }
    }
}
