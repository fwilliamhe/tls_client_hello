# tls_client_hello
## Build
This project use `vcpkg` to install dependences `brotli, boringssl, boost-asio`
```bash
cd <PATH TO VCPKG>
./vcpkg install brotli boringssl boost-asio
```
## Brief view
It can produce the same JA4+ TLS ClinetHello fingerprint as Chrome (t13d1516h2_8daaf6152771_02713d6af862).

As Chrome arranges the extensions randomly now, JA4 fingerprint doesn't value any more.

## License
GPLv3