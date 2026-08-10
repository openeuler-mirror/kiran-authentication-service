
# kiran-authentication-service

Provides system account authentication, supporting multiple authentication methods including fingerprint, facial recognition, and UKEY.

# Dependencies

```bash
yum install glib-2.0-devel zlog-devel json-glib-1.0-devel kiran-cc-daemon-devel
```

# Build

```bash
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
```

# Installation

```bash
cmake install
```

# PAM Module

`pam_kiran_authentication.so` listens for authentication result signals and processes the authentication outcomes.
