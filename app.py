# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, redirect, url_for, session, flash
import hashlib, base64, json
from io import BytesIO
import qrcode
from fpdf import FPDF
from PIL import Image
import datetime
from crypto_utils import encrypt_rsa, decrypt_rsa, sha256_hash, generate_keys_auto
import re
import os

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

    timestamp_now = datetime.datetime.now()
    timestamp_display = timestamp_now.strftime("%Y-%m-%d %H:%M:%S")
    timestamp_filename = timestamp_now.strftime("%Y-%m-%d_%H%M%S")

    if algorithm == 'rsa':
        e, d, n = generate_keys_auto()

        hashed_msg = sha256_hash(content)
        signature = encrypt_rsa(hashed_msg, d, n)
        signature_no_comma = "".join(signature.split(","))

        filename = f"signature_{timestamp_filename}.pdf"
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0, 10, "Signature (Encrypted Hash):")
        pdf.multi_cell(0, 10, signature_no_comma)
        pdf.ln(2)
        pdf.multi_cell(0, 10, f"Waktu Tanda Tangan: {timestamp_display}")

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

        pdf_bytes = pdf.output(dest='S').encode('latin-1')
        output_dir = os.path.join("static", "signed_files")
        os.makedirs(output_dir, exist_ok=True)
        file_path = os.path.join(output_dir, filename)
        with open(file_path, "wb") as f:
            f.write(pdf_bytes)

        base_url = request.host_url.rstrip('/')
        public_url = f"{base_url}/static/signed_files/{filename}"

        qr = qrcode.make(public_url)
        qr_buffer = BytesIO()
        qr.save(qr_buffer, format='PNG')
        qr_b64 = base64.b64encode(qr_buffer.getvalue()).decode()

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
        return redirect(url_for('dashboard'))
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
