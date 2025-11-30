from flask import (
    Flask,
    request,
    render_template,
    jsonify,
    abort,
    Response
)
from crypto_utils import (
    sha256_bytes,
    generate_ecdsa_keypair,
    sign_message,
    verify_signature,
)
from blockchain_ext import CertificateBlockchain
import os

app = Flask(__name__)

# Folder where uploaded certificate files will be stored
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ------------------------------------------------------
# Backend issuer keypair (used for all certificate issuing)
# In a real system, this would be securely stored, not in code.
# ------------------------------------------------------
ISSUER_PRIVATE_PEM, ISSUER_PUBLIC_PEM = generate_ecdsa_keypair()

# Single blockchain instance for the app
cert_chain = CertificateBlockchain()


# ======================================================
# Home Page
# ======================================================
@app.route('/')
def index():
    return render_template('index.html')


# ======================================================
# Generate / Show Issuer Keypair (demo only)
# ======================================================
@app.route('/keys', methods=['GET'])
def keys():
    """
    For demo: expose the fixed issuer keypair as plain text.
    In a real system, you would NEVER expose the private key.
    """
    body = (
        ISSUER_PRIVATE_PEM.strip()
        + "\n\n"
        + ISSUER_PUBLIC_PEM.strip()
        + "\n"
    )
    return Response(body, mimetype="text/plain")


# ======================================================
# Issue Certificate
# ======================================================
@app.route('/issue', methods=['GET', 'POST'])
def issue():
    if request.method == 'GET':
        return render_template('issue.html')

    issuer = request.form.get('issuer')
    student_name = request.form.get('student_name')
    student_id = request.form.get('student_id')
    degree = request.form.get('degree')

    if 'certificate_file' not in request.files or request.files['certificate_file'].filename == '':
        return abort(400, 'certificate_file missing')

    f = request.files['certificate_file']
    filename = f"{student_id}_{f.filename}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    f.save(path)

    # Hash the certificate file
    with open(path, 'rb') as fh:
        data = fh.read()

    cert_hash = sha256_bytes(data)

    # Sign with backend issuer private key
    try:
        signature = sign_message(ISSUER_PRIVATE_PEM, cert_hash.encode())
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': f'Failed to sign certificate: {str(e)}'
        }), 400

    # Create transaction on blockchain
    tx, block = cert_chain.create_certificate_tx(
        issuer=issuer or 'Demo-University',
        issuer_pubkey=ISSUER_PUBLIC_PEM,
        student_name=student_name,
        student_id=student_id,
        degree=degree,
        cert_hash=cert_hash,
        signature=signature
    )

    # For now, return JSON (good for debugging / Postman)
    return jsonify({
        'status': 'issued',
        'tx': tx,
        'block': block
    })


# ======================================================
# Verify Certificate
# ======================================================
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'GET':
        return render_template('verify.html')

    # Accept file upload OR direct hash input
    if 'certificate_file' in request.files and request.files['certificate_file'].filename != '':
        f = request.files['certificate_file']
        data = f.read()
        cert_hash = sha256_bytes(data)
    else:
        cert_hash = request.form.get('cert_hash')

    if not cert_hash:
        return abort(400, 'no certificate file or hash provided')

    # Look up transaction on blockchain
    tx, block = cert_chain.find_tx_by_hash(cert_hash)
    if not tx:
        return jsonify({
            'verified': False,
            'reason': 'No matching certificate found'
        })

    issuer_pub = tx.get('issuer_pubkey', '')
    sig_hex = tx.get('signature', '')

    sig_ok = False
    if issuer_pub and sig_hex:
        try:
            sig_ok = verify_signature(issuer_pub, cert_hash.encode(), sig_hex)
        except Exception:
            sig_ok = False

    # Return only the important fields
    return jsonify({
        'verified': sig_ok,
        'student_name': tx.get('student_name'),
        'student_id': tx.get('student_id'),
        'degree': tx.get('degree'),
        'issuer': tx.get('issuer'),
        'issue_date': tx.get('issue_date'),
        'timestamp': tx.get('timestamp')
    })


# ======================================================
# View Full Blockchain (for demo)
# ======================================================
@app.route('/chain', methods=['GET'])
def chain():
    return jsonify(cert_chain.to_dict())


# ======================================================
# Run App
# ======================================================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
