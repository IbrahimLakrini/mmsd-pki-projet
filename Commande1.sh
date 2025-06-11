# Initialize CA directories
cd root-ca
mkdir certs crl newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial

# Generate root CA private key (keep this VERY secure)
openssl genrsa -aes256 -out private/root-ca.key.pem 4096
chmod 400 private/root-ca.key.pem

# Generate self-signed root certificate
openssl req -config ../openssl-root.cnf \
      -key private/root-ca.key.pem \
      -new -x509 -days 7300 -sha256 -extensions v3_ca \
      -out certs/root-ca.cert.pem

# Verify root certificate
openssl x509 -noout -text -in certs/root-ca.cert.pem