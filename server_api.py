from fastapi import FastAPI, HTTPException, Request, Header
from pydantic import BaseModel
import hmac, hashlib, json, base64, time
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

#from Crypto.Cipher import AES
#from Crypto.Util.Padding import pad

app = FastAPI()

# ─────────────────────────────────────────────
# 🔐 CONFIG (KEEP SECRET)
# ─────────────────────────────────────────────
SECRET_KEY = b'adasdassds'
AES_KEY = b'This is a secret key 01234567890'
IV = b'16_byte_iv_limit'

API_KEY = "secret123"  # 🔴 must match client

# ─────────────────────────────────────────────
# 🗂️ IN-MEMORY DATABASE (Replace later)
# ─────────────────────────────────────────────
LICENSE_DB = {}


# ─────────────────────────────────────────────
# 📦 REQUEST MODELS (Swagger UI Support)
# ─────────────────────────────────────────────
class DeviceModel(BaseModel):
    device_id: str
    expiry_days: int = 30
    max_users: int = 100


class LicenseRequest(BaseModel):
    device_id: str


class RevokeRequest(BaseModel):
    device_id: str


# ─────────────────────────────────────────────
# 🔐 GENERATE ENCRYPTED LICENSE BLOB
# ─────────────────────────────────────────────
def generate_blob(expiry_days, max_users):
    expiry_ts = int(time.time()) + (expiry_days * 86400)

    payload = f"{expiry_ts}|{max_users}"
    signature = hmac.new(SECRET_KEY, payload.encode(), hashlib.sha256).hexdigest()
    token = f"{payload}.{signature}"

    data = {
        "token": token,
        #"registration_count": 0,
        "system_mode": "24/7"
    }

    cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)
    encrypted = cipher.encrypt(pad(json.dumps(data).encode(), 16))

    return base64.b64encode(encrypted).decode()


# ─────────────────────────────────────────────
# 🔑 API KEY VALIDATION
# ─────────────────────────────────────────────
def verify_api_key(x_api_key: str):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")


# ─────────────────────────────────────────────
# 📡 GET LICENSE
# ─────────────────────────────────────────────
@app.post("/api/get-license")
async def get_license(
    req: LicenseRequest,
    x_api_key: str = Header(None)
):
    verify_api_key(x_api_key)

    device_id = req.device_id

    license_info = LICENSE_DB.get(device_id)

    if not license_info:
        raise HTTPException(status_code=403, detail="Device not registered")

    if license_info["revoked"]:
        raise HTTPException(status_code=403, detail="License revoked")

    blob = generate_blob(
        license_info["expiry_days"],
        license_info["max_users"]
    )

    return {
        "status": "success",
        "data": blob
    }


# ─────────────────────────────────────────────
# ➕ ADD DEVICE
# ─────────────────────────────────────────────
@app.post("/api/add-device")
async def add_device(
    device: DeviceModel,
    x_api_key: str = Header(None)
):
    verify_api_key(x_api_key)

    LICENSE_DB[device.device_id] = {
        "expiry_days": device.expiry_days,
        "max_users": device.max_users,
        "revoked": False
    }

    return {
        "status": "device_added",
        "device_id": device.device_id
    }


# ─────────────────────────────────────────────
# ❌ REVOKE DEVICE
# ─────────────────────────────────────────────
@app.post("/api/revoke")
async def revoke_device(
    req: RevokeRequest,
    x_api_key: str = Header(None)
):
    verify_api_key(x_api_key)

    if req.device_id in LICENSE_DB:
        LICENSE_DB[req.device_id]["revoked"] = True
        return {"status": "revoked"}

    return {"status": "not_found"}


# ─────────────────────────────────────────────
# 📋 LIST DEVICES (DEBUG)
# ─────────────────────────────────────────────
@app.get("/api/list-devices")
async def list_devices(x_api_key: str = Header(None)):
    verify_api_key(x_api_key)
    return LICENSE_DB
