# Brightloop API

1. Create a Postgres database and copy `.env.example` to `.env` (fill in values).
2. `npm install`
3. `export $(cat .env | xargs) && npm run db:init`
4. Create the first admin: `INSERT INTO users(email,password_hash,role) VALUES ('you@company.com','<bcrypt hash>','admin');`
   (hash a password with: `node -e "console.log(require('bcryptjs').hashSync('Your@Password1',10))"`)
5. `npm start`

Main routes: /auth/*, /products, /plans, /taxes, /discounts, /subscriptions, /billing/run, /invoices, /invoices/:id/payments, /reports/summary

## Run with Docker (easiest)

    docker compose up --build

API on http://localhost:3000. Database and demo data (admin, staff, products, plans, a discount) are created on first start.
Reset everything with `docker compose down -v`. Sign in: POST /auth/login with admin@brightloop.com / Admin@12345.

## Web app

`public/index.html` is served by the API itself. After `docker compose up --build`, open http://localhost:3000 and sign in with the seeded admin.

## Email, online payments and tests

- **Password reset emails:** set `RESEND_API_KEY` and `MAIL_FROM` (and `APP_URL`, the public address of your site). Without them, emails print in the server log.
- **Online card payments (Stripe):** set `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET`. In the Stripe dashboard, add a webhook to `APP_URL/webhooks/stripe` for the `checkout.session.completed` event. Customers then see a "Pay online" button on confirmed invoices. Without the keys the button explains that online payment is not set up.
- **Tests:** with the API running on seeded data, run `npm test` (set `BASE_URL` if it is not on localhost:3000).
