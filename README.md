# Aptos Passkey WebAuthn Demo

A comprehensive demonstration of passkey authentication on the Aptos blockchain using WebAuthn technology. This React application showcases how to create, manage, and use passkeys for secure Web3 transactions without traditional passwords.

## 🚀 Features

- **🔐 Passkey Creation**: Generate secure passkey credentials using WebAuthn
- **✍️ Transaction Signing**: Sign blockchain transactions with biometric authentication
- **👁️ Credential Management**: View and manage your Aptos address and public keys
- **🚀 Real Transactions**: Submit actual transfer transactions on Aptos networks
- **🌐 Multi-Network Support**: Works with Devnet, Testnet, and Mainnet
- **💰 Balance Management**: Check APT balances and request test tokens
- **📱 Cross-Platform**: Works across devices and browsers with biometric support

## 🛠️ Technology Stack

- **Frontend**: React 18 + TypeScript + Vite
- **Blockchain**: Aptos SDK (@aptos-labs/ts-sdk)
- **Authentication**: WebAuthn API + @simplewebauthn
- **Cryptography**: @noble/curves + @noble/hashes
- **Styling**: CSS3 with modern UI components

## 🎯 What are Passkeys?

Passkeys provide a more secure and user-friendly alternative to traditional passwords by using:

- **Biometric Authentication**: Fingerprint, face recognition, or device PINs
- **Enhanced Security**: No passwords to steal or phish
- **Faster Authentication**: One-touch verification
- **Cross-Platform**: Works across devices and browsers
- **Blockchain Ready**: Seamless Web3 transaction signing

## 🚀 Quick Start

### Prerequisites

- Node.js 16+ and pnpm
- Modern browser with WebAuthn support (Chrome 67+, Firefox 60+, Safari 13+, Edge 79+)
- Device with biometric authentication capability (recommended)

### Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd passkeys-ts
   ```

2. **Install dependencies**

   ```bash
   pnpm install
   ```

3. **Start development server**

   ```bash
   pnpm dev
   ```

4. **Open your browser**
   Navigate to `http://localhost:5173`

## 📖 How to Use

### 1. Create a Passkey

- Click "Create Passkey" to generate a new WebAuthn credential
- Use your device's biometric authentication (fingerprint, face ID, etc.)
- Your passkey is securely stored locally and ready for use

### 2. Sign Transactions

- Click "Sign with Passkey" to test your passkey authentication
- Experience secure transaction signing without passwords
- View detailed signature information and transaction data

### 3. View Credentials

- Click "View Address & Keys" to see your Aptos address and public key
- Copy credentials for external use or backup
- All information is derived from your passkey

### 4. Submit Real Transactions

- Click "Submit Transfer" to send actual APT tokens
- Select your preferred network (Devnet/Testnet/Mainnet)
- Check balances and request test tokens from faucets
- Monitor transaction status in real-time

## 🌐 Supported Networks

| Network     | Purpose                | Faucet Available | Explorer                                   |
| ----------- | ---------------------- | ---------------- | ------------------------------------------ |
| **Devnet**  | Development & Testing  | ✅ Yes           | [Explorer](https://explorer.aptoslabs.com) |
| **Testnet** | Pre-production Testing | ✅ Yes           | [Explorer](https://explorer.aptoslabs.com) |
| **Mainnet** | Production             | ❌ No            | [Explorer](https://explorer.aptoslabs.com) |

## 🔧 Technical Details

### WebAuthn Implementation

- **Algorithm**: ECDSA P-256 (secp256r1)
- **Key Type**: Public-key credentials
- **User Verification**: Required
- **Resident Key**: Preferred (when supported)

### Aptos Integration

- **Address Derivation**: Secp256r1PublicKey → AuthKey → Aptos Address
- **Transaction Signing**: WebAuthn signature with authenticator data
- **Network Support**: Full Aptos network compatibility

### Security Features

- **Local Storage**: Credentials stored securely in browser
- **Biometric Protection**: Device-level authentication required
- **No Server Dependencies**: Fully client-side implementation
- **Open Standards**: Built on W3C WebAuthn specification

## 🛡️ Browser Compatibility

| Browser | Minimum Version | WebAuthn Support | Biometric Support |
| ------- | --------------- | ---------------- | ----------------- |
| Chrome  | 67+             | ✅ Full          | ✅ Yes            |
| Firefox | 60+             | ✅ Full          | ✅ Yes            |
| Safari  | 13+             | ✅ Full          | ✅ Yes            |
| Edge    | 79+             | ✅ Full          | ✅ Yes            |

## 📁 Project Structure

```
src/
├── App.tsx              # Main application component
├── helper/
│   └── webauthn.ts      # WebAuthn and Aptos integration logic
├── assets/              # Static assets
└── main.tsx            # Application entry point
```

## 🔍 Key Functions

- `createCredential()` - Create new passkey credentials
- `getCredential()` - Authenticate with existing passkey
- `submitTransfer()` - Submit blockchain transactions
- `calculateAptosAddressFromPublicKey()` - Derive Aptos addresses
- `getAptBalance()` - Check account balances

## 🚨 Important Notes

- **HTTPS Required**: WebAuthn requires secure context (HTTPS or localhost)
- **Biometric Device**: Physical device with biometric capabilities recommended
- **Test Networks**: Use Devnet/Testnet for testing, Mainnet for production
- **Credential Storage**: Credentials are stored locally in browser storage

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Links

- [Aptos Documentation](https://aptos.dev/)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [SimpleWebAuthn Library](https://simplewebauthn.dev/)
- [Aptos TypeScript SDK](https://github.com/aptos-labs/aptos-ts-sdk)

## 📞 Support

For questions or issues:

- Open an issue on GitHub
- Check the Aptos documentation
- Review WebAuthn browser compatibility

---

**Built with ❤️ for the Aptos ecosystem**
