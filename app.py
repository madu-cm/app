import os
import qrcode
import streamlit as st
from PIL import Image
from io import BytesIO
from zipfile import ZipFile
from pyzbar.pyzbar import decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from secretsharing import SecretSharer

# --- Cryptographic Functions ---
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password.encode())

def encrypt_secret(secret: str, password: str) -> str:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, secret.encode(), None)
    combined = salt + nonce + ciphertext
    return combined.hex()

def decrypt_secret(secret_hex: str, password: str) -> str:
    combined = bytes.fromhex(secret_hex)
    salt = combined[:16]
    nonce = combined[16:28]
    ciphertext = combined[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()

# --- QR Code Utilities ---
def generate_qr_code(data: str) -> BytesIO:
    img = qrcode.make(data)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return buffer

def decode_qr_image(uploaded_file) -> str:
    img = Image.open(uploaded_file)
    decoded = decode(img)
    if decoded:
        return decoded[0].data.decode()
    return None

# --- Streamlit UI ---
st.set_page_config(page_title="SecureAuth Platform", layout="centered")

# Custom CSS for improved UI
st.markdown("""
    <style>
        html, body, [class*="css"]  {
            font-family: 'Segoe UI', sans-serif;
            font-size: 18px;
        }
        .stButton>button {
            font-size: 18px;
            padding: 0.75em 1.5em;
        }
    </style>
""", unsafe_allow_html=True)

st.title("🔐 SecureAuth Platform")
st.markdown("""
### Multi-factor authorization using QR codes & Shamir's Secret Sharing
Secure, auditable, and cryptographically protected.
""")

menu = st.sidebar.selectbox("Navigation", ["Home", "Encrypt & Split", "Recover Secret", "Security Status"])

if menu == "Home":
    st.header("🛠️ Admin Setup")
    st.markdown("Configure mission parameters and generate QR tokens.")

elif menu == "Encrypt & Split":
    st.header("📸 Encrypt & Generate QR Shares")
    secret = st.text_input("Enter secret message")
    password = st.text_input("Enter encryption password", type="password")
    n = st.number_input("Total number of shares", min_value=2, max_value=10, step=1)
    k = st.number_input("Threshold to reconstruct", min_value=2, max_value=10, step=1)

    generate = st.button("🔐 Generate QR Codes")

    if generate:
        if not (secret and password and n >= k):
            st.error("Please fill all fields and ensure n ≥ k")
        else:
            encrypted = encrypt_secret(secret, password)
            shares = SecretSharer.split_secret(encrypted, int(k), int(n))
            st.success(f"Generated {n} QR Code Shares")

            zip_buffer = BytesIO()
            with ZipFile(zip_buffer, "w") as zipf:
                for i, share in enumerate(shares):
                    img_buffer = generate_qr_code(share)
                    zipf.writestr(f"share_{i+1}.png", img_buffer.getvalue())
                    st.image(img_buffer, caption=f"Share {i+1}", width=220)

            zip_buffer.seek(0)
            st.download_button(
                label="⬇️ Download All Shares as ZIP",
                data=zip_buffer,
                file_name="qr_shares.zip",
                mime="application/zip"
            )

elif menu == "Recover Secret":
    st.header("📂 Recover Secret from QR Codes")
    uploaded_files = st.file_uploader("Upload at least threshold number of QR codes", accept_multiple_files=True, type=['png'])

    if uploaded_files:
        shares = []
        for file in uploaded_files:
            data = decode_qr_image(file)
            if data:
                shares.append(data)

        password = st.text_input("Enter decryption password", type="password", key="decrypt_password")
        if st.button("🧩 Recover Secret"):
            if len(shares) < 2:
                st.warning("Please upload at least two valid QR codes.")
            elif not password:
                st.warning("Please enter the decryption password.")
            else:
                try:
                    recovered_hex = SecretSharer.recover_secret(shares)
                    secret = decrypt_secret(recovered_hex, password)
                    st.success(f"✅ Recovered Secret: {secret}")
                except Exception as e:
                    st.error(f"❌ Recovery failed: {e}")

elif menu == "Security Status":
    st.header("🛡️ Security Status Overview")
    st.markdown("""
    - *Encryption*: AES-256-GCM  
    - *Key Derivation*: PBKDF2 with SHA-256  
    - *Secret Sharing*: Shamir's Secret Sharing Scheme
    """)
    st.success("System is secure and operational.")