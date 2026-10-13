# Terrace Kit Co. backend

Node.js + Express + SQLite. It serves the storefront from `public/` and exposes a JSON API for products, accounts, checkout, payments and orders.

## Run it
```bash
npm install
cp .env.example .env      # then edit
npm start                 # http://localhost:3000
```
With no Stripe key the store runs in **test mode**: checkout works end to end, no real money moves, and card numbers are never sent to the server (card `4000 0000 0000 0002` simulates a decline).

## Take real payments (Stripe Checkout)
1. Put `STRIPE_SECRET_KEY` in `.env` (use a `sk_test_...` key first).
2. Forward webhooks while developing: `stripe listen --forward-to localhost:3000/api/stripe/webhook`, and copy the printed `whsec_...` into `STRIPE_WEBHOOK_SECRET`.
3. In production add a webhook endpoint `https://YOUR-DOMAIN/api/stripe/webhook` for `checkout.session.completed` and `checkout.session.async_payment_succeeded`.
4. Set `BASE_URL` to your public URL. Customers pay on Stripe's hosted page, so you never handle card data.

Orders are created as `pending` and become `paid` only when the signed webhook arrives. Stock is deducted at that moment.
Using Razorpay (common in India) instead: replace the `stripe.checkout.sessions.create` block in `server.js` and the webhook with Razorpay's order and signature-verification calls. Everything else stays the same.

## API
| Method and path | Purpose |
|---|---|
| GET `/api/products`, `/api/config` | Catalogue, payment mode |
| POST `/api/auth/register`, `/login`, `/logout`; GET `/api/auth/me` | Accounts (httpOnly cookie session, bcrypt) |
| POST `/api/checkout` | Validates cart and address, recomputes all prices on the server, creates the order |
| GET `/api/orders`, `/api/orders/:id` | Order history (login) and order lookup |
| POST `/api/stripe/webhook` | Payment confirmation |
| GET `/api/admin/orders`, PATCH `/api/admin/orders/:id`, PATCH `/api/admin/products/:id` | Admin, needs `x-admin-key` header |

Example: `curl -H "x-admin-key: $ADMIN_KEY" -X PATCH -H "Content-Type: application/json" -d '{"status":"shipped"}' localhost:3000/api/admin/orders/TK-XXXX`

## Security in place
Prices, shipping and tax are computed only on the server. Passwords hashed with bcrypt. Sessions in httpOnly SameSite cookies (secure in production). Rate limits on all routes, tighter on login and checkout. JSON-only writes (CSRF defence), Helmet headers with a CSP, parameterised SQL, input validation.

## Before launch
- Set `NODE_ENV=production`, a real `JWT_SECRET`, and serve over HTTPS.
- SQLite lives in `data/store.db`: host on a server with a persistent disk (Render disk, Railway volume, a VPS) and back it up. For several servers, move to Postgres.
- Add order and password-reset emails (Resend, SES or Brevo) where an order becomes paid (`markPaid`).
- Replace the placeholder products, policies and contact details, and edit prices in `server.js` seed data or via the admin route.
- Stock is checked at checkout and deducted on payment, so two simultaneous buyers of the last item could both succeed. Add stock holds if you sell limited drops.

## Admin panel
Set `ADMIN_KEY` in `.env` (a long random string), restart, then open `http://localhost:3000/admin` and enter the key.
You can see revenue and orders waiting to ship, open any order for items, address and phone, change its status
(paid, shipped, delivered, cancelled), edit product prices and stock, and export orders to CSV.
The key is held only for the browser session. Always serve the site over HTTPS in production.
