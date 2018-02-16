# HTTP Proxy

### Generating Certificates
```sh
openssl req -x509 -nodes -newkey rsa:4096 -keyout server.key.pem -out server.cert.pem -days 7300
```

```sh
openssl genrsa -aes256 -passout pass:1 -out mitmca.key.pem 4096
openssl rsa -passin pass:1 -in mitmca.key.pem -out mitmca.key.pem.tmp
mv mitmca.key.pem.tmp mitmca.key.pem
openssl req -x509 -key mitmca.key.pem -sha256 -extensions v3_ca -new -out mitmca.crt.pem -days 7300
```
