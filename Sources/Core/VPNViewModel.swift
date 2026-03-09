//
//  VPNViewModel.swift
//  secybers-vpn
//
//  Created by Ahmet Yunus BAYRAM on 13.03.2025.
//

import SwiftUI

public class VPNViewModel : ObservableObject{
    @Published public var connection: Connection
    public var profile: Profile

    public static let shared = VPNViewModel()

    public init() {
        profile = Profile(profileName: "default", profileId: "default")
        connection = Connection(profile: profile)
    }
    
    /// Set main button action according to connection status
    func mainButtonAction() {

        switch connection.connectionStatus {
        case .invalid, .disconnected:
            connection.startVPN()
            break
        case .connecting, .connected, .reasserting:
            connection.stopVPN()
            break
        case .disconnecting:
            break
        @unknown default:
            connection.startVPN()
            break
        }
    }
    
    /// Define message color according to its level
    func messageColor() -> Color {
        switch connection.message.level {
            case .error: return .red
            case .success: return .green
            case .alert: return .yellow
            case .message: return Color(UIColor.secondaryLabel)
        }
    }

    /// Define log entry color according to its level
    func logColor(logLevel: Log.LogLevel) -> Color {
        switch logLevel {
        case .debug:
            return Color(UIColor.secondaryLabel)
        case .info, .notice:
            return Color(UIColor.label)
        case .warning:
            return .yellow
        case .error, .critical, .alert, .emergency:
            return .red
        }
    }
    
    /// Add new entry to DNS list
    func addDns() {
        profile.dnsList.append("")
    }
    
  
    /// Ignore debug level entries if app is not in debug mode
    var filteredLog: [Log] {
        #if DEBUG
        return connection.output
        #else
        return connection.output.filter { $0.level != .debug }
        #endif
    }
}
