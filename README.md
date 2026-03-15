# ScriptGuard

A full-stack script protection and licensing platform.

## Project Structure

```
scriptguard/
  backend/
    server.js          - Express server entry point
    db.js              - SQLite database setup
    middleware/
      auth.js          - JWT & API key middleware
    routes/
      auth.js          - Register, login, profile
      scripts.js       - Script CRUD
      keys.js          - Key generation, verify endpoint
      stats.js         - Analytics & blacklist
  frontend/
    index.html         - Landing page
    login.html         - Sign in / register
    dashboard.html     - Full dashboard UI
```

## Setup

### 1. Install dependencies

```bash
cd backend
npm install
```

### 2. Start the server

```bash
npm start
# or for development with auto-reload:
npm run dev
```

Server runs on **http://localhost:3000**

The frontend is served automatically from the `/frontend` folder.

### 3. Open in browser

```
http://localhost:3000
```

---

## API Reference

### Auth

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/auth/register | Create account |
| POST | /api/auth/login | Sign in |
| GET  | /api/auth/me | Current user |
| POST | /api/auth/regenerate-key | New API key |

### Scripts

| Method | Path | Description |
|--------|------|-------------|
| GET    | /api/scripts | List all scripts |
| POST   | /api/scripts | Create script |
| PATCH  | /api/scripts/:id | Update script |
| DELETE | /api/scripts/:id | Delete script |

### License Keys

| Method | Path | Description |
|--------|------|-------------|
| GET    | /api/keys | List keys |
| POST   | /api/keys | Generate keys (count: 1-500) |
| PATCH  | /api/keys/:id | Update key |
| DELETE | /api/keys/:id | Delete key |
| POST   | /api/keys/verify | **Public** — verify a key from your script |

### Verify endpoint (call from your script)

```
POST http://localhost:3000/api/keys/verify
Content-Type: application/json

{
  "key": "SG-XXXXXX-XXXXXX-XXXXXX-XXXXXX",
  "script_id": 1,
  "hwid": "optional-hardware-id"
}
```

Response:
```json
{ "valid": true, "expires_at": null, "executions": 1 }
{ "valid": false, "reason": "Key has expired" }
```

### Stats

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/stats/overview | Dashboard stats |
| GET | /api/stats/executions | Execution log |

### Blacklist

| Method | Path | Description |
|--------|------|-------------|
| GET    | /api/blacklist | List entries |
| POST   | /api/blacklist | Add entry (type: hwid/ip/key) |
| DELETE | /api/blacklist/:id | Remove entry |

---

## Plan limits

| Plan | Scripts | Keys |
|------|---------|------|
| free | 1 | 50 |
| pro | 10 | Unlimited |
| enterprise | Unlimited | Unlimited |

To change a user's plan manually:
```bash
# SQLite CLI
sqlite3 backend/scriptguard.db
UPDATE users SET plan = 'pro' WHERE email = 'you@example.com';
```

---

## Deployment

1. Set `JWT_SECRET` environment variable to a strong random string
2. Set `PORT` if not using 3000
3. Serve the `frontend/` folder via nginx or any static host
4. Point the `API` constant in all frontend JS to your production URL

```bash
JWT_SECRET=your-secret PORT=8080 node server.js
```
