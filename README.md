# Secybers VPN — Open Source WireGuard Client Layer

This repository contains the core WireGuard connection layer of the [Secybers VPN](https://secybers.com) iOS app, published as transparent proof of our **no-logs policy**.

## Why we open-sourced this

We believe trust must be earned with code, not just words. This repository lets anyone verify that:

- ✅ No user traffic is logged
- ✅ No DNS queries are stored
- ✅ Private keys are generated on-device and stored in the iOS Keychain — never sent to our servers
- ✅ WireGuard keys are ephemeral — a new key pair is created per session and removed on disconnect

## What's included

| File | Purpose |
|------|---------|
| `Sources/Core/Connection.swift` | WireGuard session management, key generation, peer registration |
| `Sources/Core/PacketTunnelProvider.swift` | Network tunnel configuration, WireGuard handshake |
| `Sources/Core/VPNViewModel.swift` | UI state management |
| `Sources/Core/KeychainHelper.swift` | Secure private key storage using iOS Keychain |
| `Sources/WireGuardKit/` | WireGuard protocol implementation |

## How we prove no-logs

1. **Private key generation** — See `Connection.swift` → `getOrCreatePrivateKey()`. Keys are created with `CryptoKit` on-device and saved to Keychain only.
2. **Peer registration** — See `Connection.swift` → `registerPeer()`. Only the client's **public key** is sent to our API — never traffic, DNS queries, or IP activity.
3. **Peer removal** — See `Connection.swift` → `removePeer()`. The WireGuard peer is removed from the server on disconnect.
4. **Tunnel configuration** — See `PacketTunnelProvider.swift`. Standard WireGuard setup with no logging hooks.

## What's not included

The full app (UI, payment system, backend API) remains closed-source. This repository contains only the connection layer relevant to our privacy claims.

## Full app

Available on the [App Store](https://apps.apple.com/app/secybers-vpn/id6744368005).

## License

MIT
