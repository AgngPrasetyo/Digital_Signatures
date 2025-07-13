# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, redirect, url_for, session, flash
import hashlib, base64, json
from io import BytesIO
import qrcode
from fpdf import FPDF
from PIL import Image
import datetime
from crypto_utils import encrypt_rsa, decrypt_rsa, sha256_hash, generate_keys_auto
import re, os

# Jika belum terpasang, install zoneinfo backport atau pytz:
# pip install backports.zoneinfo pytz

app = Flask(__name__)
app.secret_key = "s3cr3t_key"

@app.after_request
def add_cache_control(response):
    if request.path == "/verify_file":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response

@app.route('/')
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/generate_rsa')
def generate_rsa():
    return render_template('Web.html')

@app.route('/sign_and_generate_qr', methods=['POST'])
def sign_and_generate_qr():
    content = request.form.get('content', '')
    algorithm = request.form.get('algorithm', '')
    signature_img_data = request.form.get('signature_image', '')

    if not content:
        return "Pesan tidak boleh kosong", 400

    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo("Asia/Jakarta")
    except ImportError:
        import pytz
        tz = pytz.timezone("Asia/Jakarta")
    now = datetime.datetime.now(tz)
    display_ts = now.strftime("%Y-%m-%d %H:%M:%S")
    file_ts    = now.strftime("%Y-%m-%d_%H%M%S")

    if algorithm == 'rsa':
        e, d, n = generate_keys_auto()

        hashed_msg = sha256_hash(content)
        signature  = encrypt_rsa(hashed_msg, d, n)

        # Buat PDF
        filename = f"signature_{file_ts}.pdf"
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0, 10, "Signature (Encrypted Hash):")
        pdf.multi_cell(0, 10, signature)
        pdf.ln(2)
        pdf.multi_cell(0, 10, f"Waktu Tanda Tangan (WIB): {display_ts}")

        # Tambahkan gambar tanda tangan jika ada
        if signature_img_data.startswith("data:image/png;base64,"):
            img_b64  = re.sub(r"^data:image/.+;base64,", "", signature_img_data)
            img_data = base64.b64decode(img_b64)
            if len(img_data) > 500:
                img = Image.open(BytesIO(img_data))
                out_dir = os.path.join("static", "signed_files")
                os.makedirs(out_dir, exist_ok=True)
                img_path = os.path.join(out_dir, f"ttd_{file_ts}.png")
                img.save(img_path)
                pdf.ln(10)
                pdf.multi_cell(0, 10, "Tanda Tangan Pengguna:")
                pdf.image(img_path, x=10, w=60)

        # Simpan PDF
        out_dir   = os.path.join("static", "signed_files")
        os.makedirs(out_dir, exist_ok=True)
        full_path = os.path.join(out_dir, filename)
        with open(full_path, "wb") as f:
            f.write(pdf.output(dest='S').encode('latin-1'))

        # Generate QR code untuk link PDF
        base_url  = request.host_url.rstrip('/')
        public_url= f"{base_url}/static/signed_files/{filename}"
        qr        = qrcode.make(public_url)
        buf       = BytesIO()
        qr.save(buf, format='PNG')
        qr_b64    = base64.b64encode(buf.getvalue()).decode()

        # Simpan hasil ke session
        session['qr']        = qr_b64
        session['pdf_url']   = public_url
        session['signature'] = signature
        session['modulus_n'] = str(n)
        session['public_e']  = str(e)

        return redirect(url_for('result'))

    return "Algoritma tidak dikenali", 400

@app.route('/result')
def result():
    qr        = session.get('qr')
    pdf_url   = session.get('pdf_url')
    signature = session.get('signature')
    modulus_n = session.get('modulus_n')
    public_e  = session.get('public_e')

    if not qr:
        return redirect(url_for('dashboard'))
    return render_template('Result.html',
                           qr=qr,
                           pdf_url=pdf_url,
                           signature=signature,
                           modulus_n=modulus_n,
                           public_e=public_e)

@app.route('/verify_file', methods=['GET', 'POST'])
def verify_file():
    if request.method == 'POST':
        sig_input = request.form.get('signature', '').strip()
        e         = request.form.get('e')
        n         = request.form.get('n')

        if not (sig_input and e and n):
            flash("Every column must be filled.", "error")
            return redirect(url_for('verify_file'))

        try:
            parts    = re.findall(r'\d+', sig_input)
            cipher   = ",".join(parts)
            decrypted= decrypt_rsa(cipher, int(e), int(n))
            valid    = not any(err in decrypted for err in [
                            "signature or key might be incorrect"
                         ])

            session['decrypted'] = decrypted
            session['valid']     = valid
            return redirect(url_for('verify_file'))

        except Exception as ex:
            flash(str(ex), "error")
            return redirect(url_for('verify_file'))

    decrypted = session.pop('decrypted', None)
    valid     = session.pop('valid', None)
    return render_template("verifikasi_file.html",
                           decrypted=decrypted,
                           valid=valid)

if __name__ == '__main__':
    app.run(debug=True)
