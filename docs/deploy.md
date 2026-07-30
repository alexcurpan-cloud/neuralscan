# NeuralScan — Deploy Guide

## Opțiunea 1: Cloudflare Tunnel (recomandat — gratuit)

```bash
# 1. Instalează cloudflared
# Windows (scoala): https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
winget install cloudflare.cloudflared

# 2. Autentifică-te
cloudflared tunnel login

# 3. Creează un tunel
cloudflared tunnel create neuralscan

# 4. Creează config
# ~\.cloudflared\config.yml:
# tunnel: <tunnel-id>
# credentials-file: ~\.cloudflared\<tunnel-id>.json
# ingress:
#   - hostname: neuralscan.yourdomain.com
#     service: http://localhost:5050
#   - service: http_status:404

# 5. DNS
cloudflared tunnel route dns neuralscan neuralscan.yourdomain.com

# 6. Rulează
cloudflared tunnel run neuralscan
```

## Opțiunea 2: Render (free tier)

1. Fork proiectul pe GitHub
2. Creează un Web Service pe Render → link repo
3. Start command: `gunicorn src.app:app`
4. Se deschide singur URL

## Opțiunea 3: Railway (free tier)

1. `railway login`
2. `railway init`
3. `railway up`

## Opțiunea 4: Local-only (default)

```bash
python src/app.py
# → http://localhost:5050
```
