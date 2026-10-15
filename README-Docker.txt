# ScamShield AI — Docker Setup

## Files Included

- `backend/Dockerfile`
- `frontend/Dockerfile`
- `frontend/nginx/default.conf`
- `frontend/src/App.tsx` — complete replacement with configurable API URL
- `docker-compose.yml`
- Root, backend and frontend `.dockerignore` files

## Prerequisites

- Docker Desktop installed and running
- Existing ScamShield AI project
- Root `.env` file containing your Google Safe Browsing API key

## Environment Configuration

Keep the root `.env` file local. Never copy it into a Docker image, commit it to Git, or share its contents.

The root `.env` should contain:

```dotenv
GOOGLE_SAFE_BROWSING_API_KEY=your_actual_key_here
```

Docker Compose reads this variable from the root `.env` file.

## Start the Application

Run these commands from the project root:

```powershell
docker compose config
docker compose up --build -d
docker compose ps
```

Open the application:

`http://localhost:8080`

## Verify the API

Check backend health through Nginx:

```powershell
Invoke-RestMethod http://localhost:8080/api/health
```

Test message analysis:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/analyze -ContentType 'application/json' -Body '{"message":"Hi, are we meeting for lunch today?"}'
```

## Logs and Shutdown

View logs:

```powershell
docker compose logs -f
```

Stop the containers:

```powershell
docker compose down
```

## Architecture

The frontend is exposed on port `8080`. Nginx serves the built React application and forwards `/api/*` requests to the backend service over the internal Docker network. The backend port is not published directly to the host.