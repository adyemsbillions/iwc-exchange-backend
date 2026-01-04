from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from auth import get_current_user
from database import get_db_connection
import os
import uuid
import re

router = APIRouter(prefix="/kyc", tags=["KYC"])

UPLOAD_DIR = "uploads/kyc"
os.makedirs(UPLOAD_DIR, exist_ok=True)


def is_valid_number(value: str, length: int):
    return bool(re.fullmatch(rf"\d{{{length}}}", value))


@router.post("/submit")
def submit_kyc(
    bvn: str,
    nin: str,
    address: str,

    nin_front: UploadFile = File(...),
    nin_back: UploadFile = File(...),
    selfie: UploadFile = File(...),

    email: str = Depends(get_current_user)
):
    # Validate BVN
    if not is_valid_number(bvn, 11):
        raise HTTPException(status_code=400, detail="BVN must be 11 digits")

    # Validate NIN
    if not is_valid_number(nin, 11):
        raise HTTPException(status_code=400, detail="NIN must be 11 digits")

    if len(address.strip()) < 10:
        raise HTTPException(status_code=400, detail="Invalid address")

    # Save files
    def save_file(file: UploadFile):
        filename = f"{uuid.uuid4()}_{file.filename}"
        path = os.path.join(UPLOAD_DIR, filename)
        with open(path, "wb") as f:
            f.write(file.file.read())
        return path

    nin_front_path = save_file(nin_front)
    nin_back_path = save_file(nin_back)
    selfie_path = save_file(selfie)

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Prevent duplicate KYC
            cur.execute("SELECT id FROM kyc WHERE user_email=%s", (email,))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail="KYC already submitted")

            cur.execute("""
                INSERT INTO kyc (
                    user_email, bvn, nin, address,
                    nin_front_image, nin_back_image, selfie_image
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                email, bvn, nin, address,
                nin_front_path, nin_back_path, selfie_path
            ))

        conn.commit()
        return {"message": "KYC submitted successfully"}

    finally:
        conn.close()


@router.get("/status")
def kyc_status(email: str = Depends(get_current_user)):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT status FROM kyc WHERE user_email=%s
            """, (email,))
            row = cur.fetchone()

            if not row:
                return {"status": "not_submitted"}

            return {"status": row["status"]}

    finally:
        conn.close()
