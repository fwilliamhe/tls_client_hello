# tls_client_hello
## Build
This project use `vcpkg` to install dependences `brotli, boringssl, boost-asio`
**!!! Update: IT'S BETTER TO PUSH `0004-patch-ech-paddingsize.patch` into `<PATH TO VCPKG>/ports/boringssl` and add this patch file to `portfile.cmake` to avoid short ECH padding !!!** 
```bash
cd <PATH TO VCPKG>
./vcpkg install brotli boringssl boost-asio
```
## Brief view
It can produce the same JA4+ TLS ClinetHello fingerprint as Chrome (t13d1516h2_8daaf6152771_02713d6af862).

As Chrome arranges the extensions randomly now, JA4 fingerprint doesn't value any more.

## License
GPLv3