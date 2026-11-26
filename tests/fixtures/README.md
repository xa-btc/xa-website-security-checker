# Synthetic HTTPS fixture

`localhost-test-cert.pem` and `localhost-test-key.pem` are publicly shareable, disposable test material generated for this project on 2026-11-26. They do not authenticate any real service and must never be deployed. Tests bind only to loopback and load the certificate into a temporary Python trust context; nothing is installed into Windows. The certificate's ten-year validity avoids rapid fixture expiry; regenerate it if necessary. OpenSSL is not required to run the tests because the generated fixture is included.
