# Cyber Chakshu SIEM - Master-Slave Frontend

This directory contains the frontend configured to use the **master-worker load balancer** architecture.

## Configuration

- **API URL**: `https://siem-master.tanubhavj.workers.dev`
- **Mode**: Master-worker with 10 backend workers
- **File Splitting**: Disabled (master worker handles distribution)

## Deployment

```bash
cd siem-tool/frontend-master-slave
npm install
npm run build
npx wrangler pages deploy dist --project-name=freekhana-master
```

## Development

```bash
cd siem-tool/frontend-master-slave
npm run dev
```

## Important Notes

### Cloudflare Error 1042

⚠️ **This configuration may not work with `*.workers.dev` domains**

Cloudflare prevents Workers from making subrequests to other `*.workers.dev` domains. This is a security restriction that cannot be bypassed.

**If you see Error 1042:**
1. Set up custom domains for your workers
2. Update `WORKERS` array in `siem-tool/master-worker/src/index.ts`
3. Update `.env.production` with your custom domain

### For Local Development

When running locally, update `.env.development` or set environment variable:

```bash
VITE_API_URL=http://localhost:8787 npm run dev
```

Or use the local development command that connects to localhost master worker:

```bash
# From the main frontend directory
npm run dev:master-slave
```

## File Structure

```
frontend-master-slave/
├── src/
│   ├── App.tsx          # Main app with file upload logic
│   ├── api.ts           # API client configuration
│   └── ...
├── .env.production       # Production API URL (master worker)
├── .env.development     # Development API URL
└── dist/                # Built files for deployment
