# tw — TrueMoney Voucher Proxy

Cloudflare bypass proxy for the TrueMoney gift voucher API.

## What it does

Calls `gift.truemoney.com` behind Cloudflare using a browser-mimicking HTTP/2 client:

- **TLS**: uTLS Firefox 120 fingerprint — bypasses JA3/JA4 detection
- **HTTP/2**: custom framer with Chrome-matching SETTINGS, HPACK, header ordering
- **Decompression**: auto gzip/deflate/brotli

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/{code}/{mobile}` | Redeem a voucher |
| `POST` | `/api/{code}/{mobile}/debug` | Debug redeem (requires `X-Debug-Token`) |
| `GET` | `/api/{code}/verify` | Verify voucher details |
| `POST` | `/api/verify` | Verify via JSON body |

## Usage

```bash
# Redeem
curl -X POST https://tw.oiio.download/api/VOUCHER_CODE/09XXXXXXXX

# Verify
curl https://tw.oiio.download/api/VOUCHER_CODE/verify

# Debug (with token)
curl -X POST -H "X-Debug-Token: YOUR_TOKEN" \
  https://tw.oiio.download/api/VOUCHER_CODE/09XXXXXXXX/debug
```

## Deploy

```bash
docker build -t tw .
docker run -p 3000:3000 -e TW_DEBUG_TOKEN=your_secret tw
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Listen port |
| `TW_DEBUG_TOKEN` | (empty) | Token for `/debug` endpoint |

## Architecture

```
tw ──► TrueMoney API (behind Cloudflare)
│
├── uTLS Firefox 120 TLS handshake
├── HTTP/2 Chrome SETTINGS + HPACK
└── gzip/brotli decompress
```
