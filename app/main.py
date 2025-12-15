from __future__ import annotations

import base64
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR.parent / "data"
PUBLIC_KEY_FILE = DATA_DIR / "public_key.pem"

DATA_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="Browser Signature Demo")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


class PublicKeyPayload(BaseModel):
    public_key: str


class SignaturePayload(BaseModel):
    data: str
    signature: str


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/public-key/status")
async def public_key_status() -> dict[str, bool]:
    return {"exists": PUBLIC_KEY_FILE.exists()}


@app.get("/api/public-key")
async def get_public_key() -> FileResponse:
    if not PUBLIC_KEY_FILE.exists():
        raise HTTPException(status_code=404, detail="Public key not found")
    return FileResponse(PUBLIC_KEY_FILE, media_type="application/x-pem-file", filename="public_key.pem")


@app.post("/api/public-key")
async def save_public_key(payload: PublicKeyPayload) -> dict[str, str]:
    public_key_pem = payload.public_key.strip()
    if not public_key_pem.startswith("-----BEGIN PUBLIC KEY-----"):
        raise HTTPException(status_code=400, detail="Invalid public key format")

    PUBLIC_KEY_FILE.write_text(public_key_pem)
    return {"message": "Public key saved"}


@app.post("/api/verify")
async def verify_signature(payload: SignaturePayload) -> dict[str, bool]:
    if not PUBLIC_KEY_FILE.exists():
        raise HTTPException(status_code=400, detail="No public key stored on server")

    public_key_pem = PUBLIC_KEY_FILE.read_text()
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))

    try:
        data_bytes = base64.b64decode(payload.data)
        signature_bytes = base64.b64decode(payload.signature)
    except (ValueError, TypeError) as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=400, detail="Invalid base64 payload") from exc

    # WebCrypto returns ECDSA signatures as a raw R||S byte string. Convert to
    # DER if needed so `cryptography` can verify it consistently.
    key_size_bytes = public_key.key_size // 8
    expected_raw_len = key_size_bytes * 2
    if len(signature_bytes) == expected_raw_len:
        r = int.from_bytes(signature_bytes[:key_size_bytes], "big")
        s = int.from_bytes(signature_bytes[key_size_bytes:], "big")
        signature_bytes = encode_dss_signature(r, s)

    try:
        public_key.verify(signature_bytes, data_bytes, ec.ECDSA(hashes.SHA256()))
        return {"valid": True}
    except InvalidSignature:
        return {"valid": False}


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
