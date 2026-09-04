# SOCRA AI — Frontend

React 19 + Vite frontend for the SOCRA AI Security Investigation Platform.

## Development

```bash
npm install
npm run dev
```

The dev server starts at `http://localhost:5173`.

## Build

```bash
npm run build
```

Output is in `dist/`.

## Environment Variables

Copy `.env.example` to `.env`:

- `VITE_API_URL` — Backend API base URL (default: `http://127.0.0.1:8000`)
- `VITE_WS_URL` — WebSocket base URL (default: `ws://127.0.0.1:8000`)

## Tech Stack

- React 19
- Vite 8
- Tailwind CSS 4
- Recharts (charts)
- Lucide React (icons)
- React Router 7
- Axios (HTTP client)
