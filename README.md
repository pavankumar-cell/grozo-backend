# Grozo Backend (simple file DB)

This repository contains a minimal Node.js Express backend that connects the four frontend pages in this workspace:

- `index.html` — storefront (customer)
- `host.html` — admin/host UI for product and promo edits
- `dashboard.html` — orders dashboard for admin/operator
- `deliveryboy.html` — delivery partner app

Overview
- The backend is implemented in `server.js` and stores data in `db.json` (file-backed JSON). No external database or npm dependencies are required.
- A default admin user is created on first run: `username: admin`, `password: admin123` — change this after first run.

Running

1. Ensure you have Node.js installed (v12+).
2. From this folder run:

```cmd
node server.js
```

This starts the backend on `http://localhost:3000`.

API summary
- `POST /api/auth/login` { username, password } -> { token }
- `POST /api/auth/register-delivery` { phone, name, vehicle, vehicleNo } -> { token }

- `GET /api/products`
- `POST /api/products` (admin)
- `PUT /api/products/:id` (admin)

- `POST /api/orders` (public) — creates an order
- `GET /api/orders` (admin/delivery)
- `PUT /api/orders/:id/status` (admin/delivery)
- `POST /api/orders/:id/assign-delivery` (admin)

Notes for frontends
- Update fetch/XHR requests in the four HTML apps to call the backend API root at `http://localhost:3000/api/...`.
- For protected endpoints, set header: `Authorization: Bearer <token>` (token obtained from `/api/auth/login` or `/api/auth/register-delivery`).

Persistence
- Data is saved to `db.json` in the same folder. Backups are recommended before making bulk edits.

Security
- This is a minimal demo backend for local/dev usage. Passwords are hashed with SHA-256 but no strong user management or rate-limiting is implemented. For production use, switch to a proper database, use bcrypt, TLS, and hardened auth.

-
## Connecting the Frontends

This backend is configured to accept requests only from the official frontend deployments listed below. The allowed origins are:

- `https://grozo-home.netlify.app`
- `https://grozo-admin.netlify.app`
- `https://grozo-dashboard.netlify.app`
- `https://grozo-deliverypartner.netlify.app`

There is a convenience endpoint that returns these links as JSON:

	`GET /api/frontend-links`

And short redirects:

	`GET /go/home` -> redirects to the home frontend
	`GET /go/admin` -> redirects to the admin frontend
	`GET /go/dashboard` -> redirects to the dashboard frontend
	`GET /go/delivery` -> redirects to the delivery partner frontend

If you need to allow additional origins (for local dev or other deployments), update the `ALLOWED_FRONTENDS` array in `server.js`.

Next steps I can help with
- Wire the frontends' fetch calls to the backend endpoints.
- Add JWT-based auth, password reset, or integration with SQLite/Postgres.
- Add CORS restrictions, HTTPS and environment config.
