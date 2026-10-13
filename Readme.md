---

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=wave&color=gradient&height=300&section=header&text=JWT%20Decoder%20API&fontSize=60&fontAlignY=38&desc=Decode%20FreeFire%20JSON%20Web%20Tokens%20Effortlessly&descAlignY=55&animation=twinkling" />
</p>

<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&weight=600&size=25&pause=1000&color=00C4FF&center=true&vCenter=true&width=435&lines=🔐+Decode+JWTs+Instantly;🚀+Flask-Based+API;💻+Inspect+Payloads+Easily;🧩+Developer-Friendly+Tool" alt="Typing SVG" />
</p>

<p align="center">
  <a href="https://github.com/TSun-FreeFire/TSun-FF-JwtDecode-Api/stargazers">
    <img src="https://img.shields.io/github/stars/TSun-FreeFire/TSun-FF-JwtDecode-Api?color=yellow&style=for-the-badge" />
  </a>
  <a href="https://github.com/TSun-FreeFire/TSun-FF-JwtDecode-Api/network/members">
    <img src="https://img.shields.io/github/forks/TSun-FreeFire/TSun-FF-JwtDecode-Api?color=blue&style=for-the-badge" />
  </a>
  <a href="https://github.com/TSun-FreeFire/TSun-FF-JwtDecode-Api/issues">
    <img src="https://img.shields.io/github/issues/TSun-FreeFire/TSun-FF-JwtDecode-Api?color=red&style=for-the-badge" />
  </a>
  <a href="https://github.com/TSun-FreeFire/TSun-FF-JwtDecode-Api/graphs/contributors">
    <img src="https://img.shields.io/github/contributors/TSun-FreeFire/TSun-FF-JwtDecode-Api?color=green&style=for-the-badge" />
  </a>
</p>

---

## 🧭 About the Project

> "Building the future, one line of code at a time."

**JWT Decoder API** is a lightweight and blazing-fast Flask application that allows you to **decode FreeFire JSON Web Tokens (JWT)** instantly — without needing a secret key.

Ideal for developers testing, debugging, or learning how JWT payloads work.

---

## ⚡ Features

| Emoji | Feature                   | Description                                            |
| :---: | :------------------------ | :----------------------------------------------------- |
|   🧩  | **Decode JWTs Instantly** | Extract payload data from any token without validation |
|   🕒  | **Readable Time Format**  | Converts UNIX timestamps to human-readable UTC time    |
|   🧠  | **Expiration Check**      | Detects expired tokens automatically                   |
|   🧰  | **REST API**              | `GET /decode_jwt?token=...` endpoint for programmatic use |
|   🖥️  | **Field by Field Output** | Header, payload, signature, claims and token info each in their own field |
|   🧪  | **Hardened API**          | JSON errors with correct status codes, malformed claims are reported instead of crashing |
|   🌍  | **Cross-Platform**        | Runs anywhere Flask and Python 3 are supported         |

---

## 🧱 Tech Stack

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-blue?logo=python&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/Flask-2.x-green?logo=flask&style=for-the-badge" />
  <img src="https://img.shields.io/badge/PyJWT-2.x-orange?logo=python&style=for-the-badge" />
  <img src="https://img.shields.io/badge/JSON-Data-lightgrey?logo=json&style=for-the-badge" />
</p>

---

## 🚀 Getting Started

### 📦 Installation

```bash
git clone https://github.com/TSun-FreeFire/TSun-FF-JwtDecode-Api.git
cd TSun-FF-JwtDecode-Api
```

### Install dependencies

```bash
pip install flask pyjwt
```

---

### ▶️ Usage

Run the Flask server:

```bash
python app.py
```

Then open the web UI in your browser:

```bash
http://127.0.0.1:8080/
```

Or call the REST API directly:

```bash
http://127.0.0.1:8080/decode_jwt?token=YOUR_JWT_TOKEN
```

> The Docker / VPS deployment serves the very same application on port `8078`
> (see `docker-compose.yml` and `setup-domain-in-vps.sh`).

---

## 🧑‍💻 API Reference

### `GET /decode_jwt`

| Method | Endpoint      | Parameter | Description                                     |
| :----: | :------------ | :-------- | :---------------------------------------------- |
|   GET  | `/decode_jwt` | `token`   | The JWT token to decode (query parameter)       |
|  POST  | `/decode_jwt` | `token`   | Same, as JSON/form body (for very long JWTs)    |

The token may also be sent in an `Authorization: Bearer <jwt>` header.
Whitespace, line breaks and a leading `Bearer ` prefix are ignored.

Examples:

```bash
curl "http://127.0.0.1:8080/decode_jwt?token=<your_token_here>"

curl -X POST -H "Content-Type: application/json" \
     -d '{"token":"<your_token_here>"}' \
     "http://127.0.0.1:8080/decode_jwt"
```

Example response:

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  "issued_at": "2018-01-18 01:30:22",
  "exp": "2018-01-18 02:30:22",
  "expires_at": "2018-01-18T02:30:22Z",
  "expired": true
}
```

| Field               | Description                                                                     |
| :------------------ | :------------------------------------------------------------------------------ |
| *(every claim)*     | All claims of the token, in their original order                                |
| `exp`               | The `exp` claim converted to `YYYY-MM-DD HH:MM:SS` (UTC)                        |
| `expires_at`        | The same instant as RFC 3339 / ISO 8601                                         |
| `expired`           | `true` / `false`, or `null` when `exp` is not a valid unix timestamp            |
| `issued_at`         | Readable version of `iat` (the numeric `iat` claim is kept as is)               |
| `not_before`        | Readable version of `nbf` (the numeric `nbf` claim is kept as is)              |
| `lock_region_time`  | Converted to a readable UTC date (FreeFire specific)                            |
| `expiry_warning`    | Only when `exp` exists but is not a valid timestamp                             |
| `signature_warning` | Only when the signature segment is malformed; header/payload are decoded anyway  |

### Status codes

| Code | Meaning                                                                         |
| :--: | :------------------------------------------------------------------------------ |
| 200  | Token decoded                                                                   |
| 400  | Token missing, malformed, or the payload is not a JSON object                   |
| 413  | Token longer than 16 KiB                                                        |
| 500  | Unexpected server error (always JSON, never an HTML error page)                 |

Error responses always have the same shape:

```json
{
  "error": "Invalid token",
  "details": "A JWT must have exactly 3 dot-separated parts (header.payload.signature), got 2."
}
```

`Access-Control-Allow-Origin: *` is returned on the API routes, so the endpoint can
be consumed from any browser application.

### `GET /health`

Liveness probe used by Docker and Nginx:
`{"status": "ok", "service": "tsun-ff-jwtdecode-api"}`.

---

## 🧪 Tests

```bash
python -m unittest discover -s tests -v
```

33 tests cover the API: valid, expired, malformed and edge-case tokens (string /
boolean / huge timestamps), CORS, error handling and the health endpoint.

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Open a pull request

<p align="center">
  <a href="https://github.com/TSun-FreeFire/TSun-FF-JwtDecode-Api/issues">
    <img src="https://img.shields.io/badge/🐛-Report%20Bug-critical?style=for-the-badge" />
  </a>
  <a href="https://github.com/TSun-FreeFire/TSun-FF-JwtDecode-Api/pulls">
    <img src="https://img.shields.io/badge/💡-Request%20Feature-blue?style=for-the-badge" />
  </a>
</p>

---

## 🌐 Connect with Us

<p align="center">
  <a href="https://t.me/saeedxdie">
    <img src="https://img.shields.io/badge/Telegram-Join%20Chat-blue?logo=telegram&style=for-the-badge" />
  </a>
  <a href="https://twitter.com/saeedxdie">
    <img src="https://img.shields.io/badge/Twitter-Follow%20Us-skyblue?logo=twitter&style=for-the-badge" />
  </a>
  <a href="https://instagram.com/saeedxdie">
    <img src="https://img.shields.io/badge/Instagram-Follow%20Us-pink?logo=instagram&style=for-the-badge" />
  </a>
  <a href="https://tiktok.com/@saeedxdie">
    <img src="https://img.shields.io/badge/TikTok-Follow%20Us-black?logo=tiktok&style=for-the-badge" />
  </a>
</p>

---

## 📊 GitHub Stats

<p align="center">
  <img src="https://github-readme-stats.vercel.app/api?username=saeedx302&show_icons=true&theme=radical&hide_border=true" />
  <img src="https://github-readme-streak-stats.herokuapp.com?user=saeedx302&theme=radical&hide_border=true" />
  <img src="https://github-readme-stats.vercel.app/api/top-langs/?username=saeedx302&layout=compact&theme=radical&hide_border=true" />
</p>

---

## 🪪 License

This project is licensed under the [MIT License](LICENSE).

---
