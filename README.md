# Lexora
Practice management + client intake for Canadian firms. Node/Express + SQLite, one container.

## Run locally
    npm install && npm start      # http://localhost:3000

## Deploy (Render)
1. Push this folder to a GitHub repo.
2. Render → New → Blueprint → select the repo (uses render.yaml; a persistent disk at /data holds the database).
3. Set BASE_URL to your Render URL. Optional Stripe: set STRIPE_SECRET_KEY, then add a webhook
   endpoint https://<your-url>/api/stripe-webhook for `checkout.session.completed` and set STRIPE_WEBHOOK_SECRET.
Any Docker host works (Fly.io, Railway): mount a volume at /data.

## Notes
- Sign-up creates a firm; passwords are scrypt-hashed; sessions are HttpOnly cookies.
- The server enforces trust integrity (append-only history, no negative client balances) and keeps an audit table.
- E-signature, SMS and calendar sync are still simulated. Stripe payments go to your operating account; never route operating revenue through a trust account.
- Trust logic needs review by a legal-ethics specialist before real client funds are used.
