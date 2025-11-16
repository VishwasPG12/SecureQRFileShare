import base64
from io import BytesIO
import qrcode
import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_file(file_bytes: bytes):
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(file_bytes)
    encrypted = cipher.nonce + tag + ciphertext
    return encrypted, key

def decrypt_file(encrypted_bytes: bytes, key_bytes: bytes):
    if len(encrypted_bytes) < 32:
        raise ValueError("Encrypted data is too short or corrupted.")
    nonce = encrypted_bytes[:16]
    tag = encrypted_bytes[16:32]
    ciphertext = encrypted_bytes[32:]
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def generate_qr_image(data_str: str):
    qr = qrcode.QRCode(
        version=1,
        box_size=8,
        border=4,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
    )
    qr.add_data(data_str)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    if hasattr(img, "get_image"):
        img = img.get_image()
    return img

def pil_image_to_bytes(img):
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf.getvalue()

st.set_page_config(page_title="Secure File Sharing with QR Key Exchange")
st.title("🔐 Secure File Sharing with QR-based Key Exchange")

st.write(
    """
This prototype demonstrates AES-256 encryption of files with QR-based offline key sharing.

Workflow:
1. Encrypt a file → AES key generated.
2. Key is converted to Base64 + QR code.
3. Share encrypted file normally.
4. Share key ONLY via QR.
5. Receiver decrypts using key + encrypted file.
"""
)

tab_encrypt, tab_decrypt = st.tabs(["🔒 Encrypt File", "🔓 Decrypt File"])

with tab_encrypt:
    st.subheader("Upload file to encrypt")
    enc_file = st.file_uploader("Choose any file", key="enc_file")

    if enc_file:
        file_bytes = enc_file.read()
        st.info(f"Selected: {enc_file.name} ({len(file_bytes)} bytes)")

        if st.button("Encrypt File"):
            try:
                encrypted_bytes, key_bytes = encrypt_file(file_bytes)
                key_b64 = base64.b64encode(key_bytes).decode("utf-8")

                st.success("Encrypted successfully!")
                st.code(key_b64)

                qr_img = generate_qr_image(key_b64)
                qr_bytes = pil_image_to_bytes(qr_img)

                st.image(qr_img, caption="Scan to retrieve AES key")

                enc_filename = enc_file.name + ".enc"

                st.download_button(
                    "Download Encrypted File",
                    data=encrypted_bytes,
                    file_name=enc_filename,
                    mime="application/octet-stream",
                )

                st.download_button(
                    "Download QR Code",
                    data=qr_bytes,
                    file_name="encryption_key_qr.png",
                    mime="image/png",
                )

            except Exception as e:
                st.error(f"Encryption failed: {e}")

with tab_decrypt:
    st.subheader("Upload encrypted file (.enc)")
    dec_file = st.file_uploader("Upload encrypted file", key="dec_file")

    key_input = st.text_input(
        "Paste AES key (Base64)",
        type="password",
    )

    if st.button("Decrypt File"):
        if not dec_file:
            st.error("Upload an encrypted file first.")
        elif not key_input.strip():
            st.error("Paste the AES key.")
        else:
            try:
                encrypted_bytes = dec_file.read()
                key_bytes = base64.b64decode(key_input.strip())
                decrypted_bytes = decrypt_file(encrypted_bytes, key_bytes)

                out_name = dec_file.name.replace(".enc", "")
                if out_name == dec_file.name:
                    out_name = "decrypted_" + dec_file.name

                st.success("Decrypted successfully!")

                st.download_button(
                    "Download Decrypted File",
                    data=decrypted_bytes,
                    file_name=out_name,
                    mime="application/octet-stream",
                )
            except Exception as e:
                st.error(f"Decryption failed: {e}")
