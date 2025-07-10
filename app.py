# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, redirect, url_for, session, flash
import hashlib, base64, json
from io import BytesIO
import qrcode
from fpdf import FPDF
from PIL import Image
import datetime
from crypto_utils import encrypt_rsa, decrypt_rsa, sha256_hash, generate_keys_auto
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
import re
import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = "s3cr3t_key"

GOOGLE_CLIENT_SECRETS_FILE = os.path.join('credential', 'client_secret.json')
SCOPES = ['https://www.googleapis.com/auth/drive.file']
GOOGLE_DRIVE_FOLDER_ID = '1qOebfm0GTlvojO7Ro6KOMmOnYJmn9FQt'

@app.after_request
def add_cache_control(response):
    if request.path == "/verify_file":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/generate_rsa')
def generate_rsa():
    return render_template('Web.html')

@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri="http://127.0.0.1:5000/oauth2callback"
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)

@app.route("/oauth2callback")
def oauth2callback():
    state = session['state']
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri="http://127.0.0.1:5000/oauth2callback"
    )
    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials
    session['credentials'] = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }
    return redirect(url_for('generate_rsa'))

@app.route('/sign_and_generate_qr', methods=['POST'])
def sign_and_generate_qr():
    from flask import request
    content = request.form.get('content', '')
    algorithm = request.form.get('algorithm', '')
    signature_img_data = request.form.get('signature_image', '')

    if not content:
        return "Pesan tidak boleh kosong", 400

    timestamp_now = datetime.datetime.now()
    timestamp_display = timestamp_now.strftime("%Y-%m-%d %H:%M:%S")
    timestamp_filename = timestamp_now.strftime("%Y-%m-%d_%H%M%S")

    if algorithm == 'rsa':
        e, d, n = generate_keys_auto()

        # Buat signature dari hash pesan
        hashed_msg = sha256_hash(content)
        signature = encrypt_rsa(hashed_msg, d, n)
        signature_no_comma = "".join(signature.split(","))

        # Buat PDF
        filename = f"signature_{timestamp_filename}.pdf"
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0, 10, "Signature (Encrypted Hash):")
        pdf.multi_cell(0, 10, signature_no_comma)
        pdf.ln(2)
        pdf.multi_cell(0, 10, f"Waktu Tanda Tangan: {timestamp_display}")

        # Tambahkan gambar tanda tangan pengguna jika ada
        if signature_img_data and signature_img_data.startswith("data:image/png;base64,"):
            img_base64 = re.sub('^data:image/.+;base64,', '', signature_img_data)
            img_data = base64.b64decode(img_base64)
            if len(img_data) > 500:
                img = Image.open(BytesIO(img_data))
                os.makedirs("static/signed_files", exist_ok=True)
                temp_path = os.path.join("static", "signed_files", f"ttd_{timestamp_filename}.png")
                img.save(temp_path)
                pdf.ln(10)
                pdf.multi_cell(0, 10, "Tanda Tangan Pengguna:")
                pdf.image(temp_path, x=10, w=60)

        # Simpan PDF ke folder static/signed_files
        pdf_bytes = pdf.output(dest='S').encode('latin-1')
        output_dir = os.path.join("static", "signed_files")
        os.makedirs(output_dir, exist_ok=True)
        file_path = os.path.join(output_dir, filename)
        with open(file_path, "wb") as f:
            f.write(pdf_bytes)

        # Buat URL publik untuk QR code
        base_url = request.host_url.rstrip('/')
        public_url = f"{base_url}/static/signed_files/{filename}"

        # Buat QR code
        qr = qrcode.make(public_url)
        qr_buffer = BytesIO()
        qr.save(qr_buffer, format='PNG')
        qr_b64 = base64.b64encode(qr_buffer.getvalue()).decode()

        # Simpan ke session untuk ditampilkan di result.html
        session['qr'] = qr_b64
        session['pdf_url'] = public_url
        session['signature'] = signature_no_comma
        session['modulus_n'] = str(n)
        session['public_e'] = str(e)

        return redirect(url_for('result'))

    return "Algoritma tidak dikenali", 400


@app.route('/result')
def result():
    qr = session.get('qr')
    pdf_url = session.get('pdf_url')
    signature = session.get('signature')
    modulus_n = session.get('modulus_n')
    public_e = session.get('public_e')

    if not qr:
        return redirect(url_for('index'))
    return render_template('Result.html', qr=qr, pdf_url=pdf_url, signature=signature, modulus_n=modulus_n, public_e=public_e)

@app.route('/verify_file', methods=['GET', 'POST'])
def verify_file():
    if request.method == 'POST':
        signature = request.form.get('signature', '').strip()
        e = request.form.get('e')
        n = request.form.get('n')

        if not e or not n or not signature:
            flash("Semua kolom harus diisi.", "error")
            return redirect(url_for('verify_file'))

        try:
            signature_clean = re.findall(r'\d+', signature)
            cleaned_signature = ",".join(signature_clean)
            decrypted = decrypt_rsa(cleaned_signature, int(e), int(n))
            valid = '[Gagal decode base64' not in decrypted

            session['decrypted'] = decrypted
            session['valid'] = valid
            return redirect(url_for('verify_file'))

        except Exception as ex:
            flash(str(ex), "error")
            return redirect(url_for('verify_file'))

    decrypted = session.pop('decrypted', None)
    valid = session.pop('valid', None)
    return render_template("verifikasi_file.html", decrypted=decrypted, valid=valid)

if __name__ == '__main__':
    app.run(debug=True)
