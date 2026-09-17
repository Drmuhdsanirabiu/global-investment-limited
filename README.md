# Global Investment Limited — Full-stack v2

## Included
- Responsive frontend using the supplied Global Investment Limited logo
- Node.js + Express backend
- SQLite database
- Registration/login/logout
- Password hashing with bcrypt
- Session authentication
- Rate limiting + Helmet security headers
- Wallet balance and transaction ledger
- Deposit flow with a Flutterwave provider adapter
- Signed Flutterwave webhook endpoint
- Withdrawal request workflow with admin approval
- Referral system
- Admin dashboard
- TOTP 2FA setup/enable/disable
- Audit logging
- Optional SMTP email adapter
- `.env.example` configuration

## Local testing
1. Install Node.js 18+.
2. Open this folder in a terminal.
3. Run `npm install`.
4. Copy `.env.example` to `.env` and change `SESSION_SECRET`.
5. Run `npm start`.
6. Open Chrome at `http://localhost:3000`.

### Demo admin
Email: `admin@globalinvestment.test`
Password: `Admin@12345`

Change the demo credentials before deployment.

## Payment setup
Set `PAYMENT_PROVIDER=flutterwave` and add the Flutterwave secret/webhook credentials in `.env`. Start with the provider's test/sandbox credentials. The server keeps secret keys out of browser JavaScript.

Flutterwave remains as the configured payment adapter. Always verify critical payment data before crediting a wallet.

## Production requirements
This project is a technical starter, not legal/compliance approval. Before accepting real public investment funds, obtain the required Nigerian regulatory authorisations, complete privacy and security controls, use HTTPS, secure persistent sessions, encrypted backups, monitoring, incident response, and an independent security review. Do not advertise guaranteed/unrealistic returns. 