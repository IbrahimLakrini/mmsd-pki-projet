import os
import sys
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from OpenSSL import crypto
from datetime import datetime, timedelta
import logging
import shutil
from werkzeug.utils import secure_filename

# Disable Flask development server warning
cli = sys.modules.get('flask.cli', None)
if cli:
    cli.show_server_banner = lambda *x: None
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.urandom(24)
# context processor

@app.context_processor
def inject_current_year():
    return {'current_year': datetime.now().year}

@app.context_processor
def inject_pki_status():
    def pki_configured():
        intermediate_ca_cert = os.path.join(PKI_DIRS['intermediate_ca'], 'certs', 'intermediate-ca.cert.pem')
        return os.path.exists(intermediate_ca_cert)
    return dict(pki_configured=pki_configured)

# Add this to your app.py right after creating the Flask app
def pki_configured():
    intermediate_ca_cert = os.path.join(PKI_DIRS['intermediate_ca'], 'certs', 'intermediate-ca.cert.pem')
    return os.path.exists(intermediate_ca_cert)

app.jinja_env.globals.update(pki_configured=pki_configured)
# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
ALLOWED_EXTENSIONS = {'pem', 'key', 'crt', 'csr'}

# Certificate storage
CERTIFICATES = []
PRIVATE_KEYS = {}
CRL_LIST = []

# PKI Directory Structure
PKI_DIRS = {
    'root_ca': os.path.join(BASE_DIR, 'ca/root-ca'),
    'intermediate_ca': os.path.join(BASE_DIR, 'ca/intermediate-ca'),
    'leaf_certs': os.path.join(BASE_DIR, 'ca/leaf-certs')
}

# Initialize directories
for dir_path in PKI_DIRS.values():
    os.makedirs(dir_path, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_ca_certificate(ca_name, common_name, organization, country, validity_days, parent_ca=None):
    """Generate CA certificate with robust error handling"""
    try:
        # Validate inputs
        if not all([common_name, organization, country]):
            raise ValueError("All certificate fields must be non-empty")
        if len(country) != 2:
            raise ValueError("Country code must be 2 characters")

        # Setup directory structure
        ca_dir = os.path.join(PKI_DIRS['root_ca' if ca_name == 'root' else 'intermediate_ca'])
        for subdir in ['private', 'certs', 'crl', 'newcerts']:
            os.makedirs(os.path.join(ca_dir, subdir), exist_ok=True)

        # Initialize certificate database
        index_path = os.path.join(ca_dir, 'index.txt')
        serial_path = os.path.join(ca_dir, 'serial')

        if not os.path.exists(index_path):
            open(index_path, 'a').close()
        if not os.path.exists(serial_path):
            with open(serial_path, 'w') as f:
                f.write('1000\n')

        # Generate key pair (use stronger RSA parameters)
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)  # Increased from 2048 to 4096

        # Create certificate with proper encoding
        cert = crypto.X509()
        cert.set_version(2)
        cert.set_serial_number(int(datetime.now().timestamp()))  # More unique serial

        # Set subject with proper encoding
        subject = cert.get_subject()
        subject.CN = common_name.encode('ascii') if isinstance(common_name, str) else common_name
        subject.O = organization.encode('ascii') if isinstance(organization, str) else organization
        subject.C = country.encode('ascii') if isinstance(country, str) else country

        # Set validity period (ensure not zero)
        validity_seconds = max(1, validity_days) * 24 * 60 * 60
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(validity_seconds)

        # Add extensions with proper encoding
        extensions = [
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE,pathlen:1"),
            crypto.X509Extension(b"keyUsage", True, b"keyCertSign,cRLSign"),
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert)
        ]

        if parent_ca:
            cert.set_issuer(parent_ca.get_subject())
            extensions.append(
                crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=parent_ca)
            )
            cert.sign(parent_ca.get_pubkey(), "sha256")
        else:
            cert.set_issuer(subject)
            cert.sign(key, "sha512")  # Stronger hash for root

        cert.add_extensions(extensions)

        # Save files with proper permissions
        key_path = os.path.join(ca_dir, 'private', f'{ca_name}-ca.key.pem')
        cert_path = os.path.join(ca_dir, 'certs', f'{ca_name}-ca.cert.pem')

        with open(key_path, 'wb') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        os.chmod(key_path, 0o400)

        with open(cert_path, 'wb') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

        return cert, key

    except Exception as e:
        logger.error(f"Certificate generation failed: {str(e)}", exc_info=True)
        raise ValueError(f"Certificate generation failed: {str(e)}") from e

@app.route('/')
def index():
    """Dashboard showing PKI status"""
    # Count certificates by type
    stats = {
        'root_ca': len([c for c in CERTIFICATES if c['type'] == 'Root CA']),
        'intermediate_ca': len([c for c in CERTIFICATES if c['type'] == 'Intermediate CA']),
        'leaf_certs': len([c for c in CERTIFICATES if c['type'] == 'Leaf Certificate']),
        'revoked': len([c for c in CERTIFICATES if c.get('status') == 'Revoked'])
    }

    return render_template('index.html', certificates=CERTIFICATES, stats=stats)


@app.route('/setup-pki', methods=['GET', 'POST'])
def setup_pki():
    """Initialize PKI hierarchy with robust validation"""
    if request.method == 'POST':
        try:
            # Validate and sanitize inputs
            fields = {
                'root_common_name': request.form.get('root_common_name', '').strip(),
                'root_organization': request.form.get('root_organization', '').strip(),
                'root_country': request.form.get('root_country', '').strip().upper()[:2],
                'intermediate_common_name': request.form.get('intermediate_common_name', '').strip(),
                'intermediate_organization': request.form.get('intermediate_organization', '').strip(),
                'intermediate_country': request.form.get('intermediate_country', '').strip().upper()[:2]
            }

            # Validate all fields
            if not all(fields.values()):
                raise ValueError("All fields are required")
            if len(fields['root_country']) != 2 or len(fields['intermediate_country']) != 2:
                raise ValueError("Country must be 2-letter code")
            if any(not s.replace(' ', '').isalnum() for s in
                   [fields['root_common_name'], fields['intermediate_common_name']]):
                raise ValueError("Common names must be alphanumeric")

            # Generate certificates with error handling
            try:
                root_cert, root_key = generate_ca_certificate(
                    'root',
                    fields['root_common_name'],
                    fields['root_organization'],
                    fields['root_country'],
                    7300  # 20 years for root
                )

                intermediate_cert, intermediate_key = generate_ca_certificate(
                    'intermediate',
                    fields['intermediate_common_name'],
                    fields['intermediate_organization'],
                    fields['intermediate_country'],
                    3650,  # 10 years for intermediate
                    root_cert
                )
            except Exception as e:
                # Clean up partial creation
                shutil.rmtree(PKI_DIRS['root_ca'], ignore_errors=True)
                shutil.rmtree(PKI_DIRS['intermediate_ca'], ignore_errors=True)
                raise

            # Store certificate info
            CERTIFICATES.extend([
                {
                    'common_name': fields['root_common_name'],
                    'organization': fields['root_organization'],
                    'country': fields['root_country'],
                    'type': 'Root CA',
                    'status': 'Active',
                    'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'expires_at': (datetime.now() + timedelta(days=7300)).strftime("%Y-%m-%d %H:%M:%S")
                },
                {
                    'common_name': fields['intermediate_common_name'],
                    'organization': fields['intermediate_organization'],
                    'country': fields['intermediate_country'],
                    'type': 'Intermediate CA',
                    'status': 'Active',
                    'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'expires_at': (datetime.now() + timedelta(days=3650)).strftime("%Y-%m-%d %H:%M:%S")
                }
            ])

            flash('PKI hierarchy successfully established!', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            flash(f'PKI setup failed: {str(e)}', 'danger')
            logger.error(f"PKI Setup Error: {str(e)}", exc_info=True)

    return render_template('setup_pki.html')

@app.route('/generate-certificate', methods=['GET', 'POST'])
def generate_certificate():  # Changed from generate_csr to match all references
    """Generate leaf certificates (replaces old generate_csr endpoint)"""
    if request.method == 'POST':
        try:
            common_name = request.form['common_name']
            organization = request.form['organization']
            country = request.form['country'].upper()[:2]
            cert_type = request.form.get('cert_type', 'server')  # Default to server cert
            validity_days = int(request.form.get('validity_days', 365))  # Default 1 year

            if not all([common_name, organization, country]):
                raise ValueError("All fields are required")
            if len(country) != 2:
                raise ValueError("Country must be 2-letter code")

            # Load intermediate CA
            ca_cert_path = os.path.join(PKI_DIRS['intermediate_ca'], 'certs', 'intermediate-ca.cert.pem')
            ca_key_path = os.path.join(PKI_DIRS['intermediate_ca'], 'private', 'intermediate-ca.key.pem')

            if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
                raise ValueError("Intermediate CA not found. Please set up PKI first.")

            with open(ca_cert_path, 'rb') as f:
                ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

            with open(ca_key_path, 'rb') as f:
                ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

            # Generate key pair
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, 2048)

            # Create certificate
            cert = crypto.X509()
            cert.set_version(2)
            cert.set_serial_number(int(datetime.now().timestamp()))

            # Set certificate subject
            subject = cert.get_subject()
            subject.CN = common_name
            subject.O = organization
            subject.C = country

            # Set validity period
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(validity_days * 24 * 60 * 60)

            # Set issuer
            cert.set_issuer(ca_cert.get_subject())

            # Add extensions based on certificate type
            if cert_type == 'server':
                cert.add_extensions([
                    crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
                    crypto.X509Extension(b"keyUsage", False, b"digitalSignature, keyEncipherment"),
                    crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"),
                    crypto.X509Extension(b"subjectAltName", False, f"DNS:{common_name}".encode())
                ])
            else:
                cert.add_extensions([
                    crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
                    crypto.X509Extension(b"keyUsage", False, b"digitalSignature"),
                    crypto.X509Extension(b"extendedKeyUsage", False, b"clientAuth")
                ])

            # Sign the certificate
            cert.sign(ca_key, "sha256")

            # Save files
            cert_dir = os.path.join(PKI_DIRS['leaf_certs'], cert_type)
            os.makedirs(cert_dir, exist_ok=True)

            key_path = os.path.join(cert_dir, f'{common_name}.key.pem')
            cert_path = os.path.join(cert_dir, f'{common_name}.crt')

            with open(key_path, 'wb') as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
            os.chmod(key_path, 0o400)

            with open(cert_path, 'wb') as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

            CERTIFICATES.append({
                'common_name': common_name,
                'organization': organization,
                'country': country,
                'type': 'Leaf Certificate',
                'cert_type': cert_type,
                'status': 'Active',
                'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'expires_at': (datetime.now() + timedelta(days=validity_days)).strftime("%Y-%m-%d %H:%M:%S"),
                'key_path': key_path,
                'cert_path': cert_path
            })

            flash(f'{cert_type.capitalize()} certificate generated successfully!', 'success')
            return redirect(url_for('view_certificates'))

        except Exception as e:
            flash(f'Error generating certificate: {str(e)}', 'danger')

    return render_template('generate.html')


@app.route('/certificates')
def view_certificates():
    """View all certificates"""
    return render_template('certificates.html', certificates=CERTIFICATES)


@app.route('/download/<path:filename>')
def download_file(filename):
    """Download certificate or key file"""
    directory = os.path.dirname(filename)
    file = os.path.basename(filename)
    return send_from_directory(directory, file, as_attachment=True)


@app.route('/revoke/<common_name>')
def revoke_certificate(common_name):
    """Revoke a certificate"""
    try:
        for cert in CERTIFICATES:
            if cert['common_name'] == common_name:
                cert['status'] = 'Revoked'
                cert['revoked_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Add to CRL
                CRL_LIST.append({
                    'serial': cert.get('serial', 'N/A'),
                    'common_name': common_name,
                    'revocation_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'reason': 'Unspecified'
                })

                break

        flash('Certificate revoked successfully!', 'warning')
    except Exception as e:
        flash(f'Error revoking certificate: {str(e)}', 'danger')

    return redirect(url_for('view_certificates'))


@app.route('/crl')
def view_crl():
    """View Certificate Revocation List"""
    return render_template('crl.html', crl_list=CRL_LIST)


@app.route('/generate-crl')
def generate_crl():
    """Generate Certificate Revocation List"""
    try:
        # Load intermediate CA
        ca_cert_path = os.path.join(PKI_DIRS['intermediate_ca'], 'certs', 'intermediate-ca.cert.pem')
        ca_key_path = os.path.join(PKI_DIRS['intermediate_ca'], 'private', 'intermediate-ca.key.pem')

        with open(ca_cert_path, 'rb') as f:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        with open(ca_key_path, 'rb') as f:
            ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

        # Create CRL
        crl = crypto.CRL()
        for revoked in CRL_LIST:
            revoked_cert = crypto.Revoked()
            revoked_cert.set_serial(revoked['serial'].encode())
            revoked_cert.set_rev_date(revoked['revocation_date'].encode())
            revoked_cert.set_reason(revoked['reason'].encode())
            crl.add_revoked(revoked_cert)

        crl.sign(ca_cert, ca_key, b'sha256')

        # Save CRL
        crl_path = os.path.join(PKI_DIRS['intermediate_ca'], 'crl', 'intermediate-ca.crl.pem')
        with open(crl_path, 'wb') as f:
            f.write(crl.export(ca_cert, ca_key, crypto.FILETYPE_PEM))

        flash('CRL generated successfully!', 'success')
    except Exception as e:
        flash(f'Error generating CRL: {str(e)}', 'danger')

    return redirect(url_for('view_crl'))


@app.route('/verify-certificate', methods=['GET', 'POST'])
def verify_certificate():
    """Verify certificate chain and validity"""
    if request.method == 'POST':
        try:
            if 'cert_file' not in request.files:
                raise ValueError("No certificate file uploaded")

            cert_file = request.files['cert_file']
            if cert_file.filename == '':
                raise ValueError("No selected file")

            if cert_file and allowed_file(cert_file.filename):
                filename = secure_filename(cert_file.filename)
                cert_path = os.path.join(UPLOAD_FOLDER, filename)
                cert_file.save(cert_path)

                with open(cert_path, 'rb') as f:
                    cert_data = f.read()

                cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

                # Load CA chain
                root_ca_path = os.path.join(PKI_DIRS['root_ca'], 'certs', 'root-ca.cert.pem')
                intermediate_ca_path = os.path.join(PKI_DIRS['intermediate_ca'], 'certs', 'intermediate-ca.cert.pem')

                with open(root_ca_path, 'rb') as f:
                    root_ca = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

                with open(intermediate_ca_path, 'rb') as f:
                    intermediate_ca = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

                # Create certificate store
                store = crypto.X509Store()
                store.add_cert(root_ca)
                store.add_cert(intermediate_ca)

                # Verify certificate
                store_ctx = crypto.X509StoreContext(store, cert)
                result = store_ctx.verify_certificate()

                # Check revocation status
                is_revoked = any(revoked['common_name'] == cert.get_subject().CN for revoked in CRL_LIST)

                return render_template('verify_result.html',
                                       cert=cert,
                                       valid=result is None,
                                       is_revoked=is_revoked,
                                       subject=cert.get_subject(),
                                       issuer=cert.get_issuer(),
                                       not_before=cert.get_notBefore(),
                                       not_after=cert.get_notAfter())

        except Exception as e:
            flash(f'Error verifying certificate: {str(e)}', 'danger')

    return render_template('verify_certificate.html')


if __name__ == '__main__':
    # Run the app
    from werkzeug.serving import WSGIRequestHandler

    WSGIRequestHandler.protocol_version = "HTTP/1.1"
    app.run(host='0.0.0.0', port=5000, debug=True)