# CONFIG="
# # Configuration for openssl req
# [ req ]
# default_bits        = 4096
# distinguished_name  = req_distinguished_name
# prompt              = no
# x509_extensions     = v3_req

# [ v3_req ]
# basicConstraints    = CA:FALSE
# extendedKeyUsage    = serverAuth, clientAuth
# subjectAltName      = IP:192.168.0.184

# [ req_distinguished_name ]
# countryName                     = RU
# stateOrProvinceName             = Tatarstan
# localityName                    = Innopolis
# organizationName                = Innopolis University
# organizationalUnitName          = BS19
# commonName                      = *

# emailAddress                   = Email Address
# "
mkdir -p result

openssl req -x509 -newkey rsa:4096 -config csr.conf -keyout result/myPrivateKey.pem -out result/certificate.crt -days 365 -nodes

openssl pkcs12 -export -out result/identity.pfx -inkey result/myPrivateKey.pem -in result/certificate.crt -passout pass:localhost