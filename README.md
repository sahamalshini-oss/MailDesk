# MailDesk

## Structure
- `backend/` — Express API, SQLite DB, uploads, env, tests
- `frontend/` — static UI (`index.html`, assets)

## Run
1. Configure env in `backend/.env` (or copy from `backend/.env.example`).
2. Install backend deps in `backend/` if needed: `cd backend && npm install`
3. Start backend: `npm run start:backend` (from root) or `node server.js` (from `backend/`)
4. Open `http://localhost:3000`

Backend serves `/api/*`, `/uploads/*`, and the frontend from `../frontend` by default (`FRONTEND_DIR` can override). DB/uploads default to `backend/data.db` and `backend/uploads/` (`DB_PATH`, `UPLOAD_DIR` can override).