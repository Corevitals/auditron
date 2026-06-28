# Auditron

> **Tomorrow's Security... Today.**

Auditron is a security inspection unit for Symfony applications. It scans your project for common security issues, insecure configurations, and development mistakes before they become production incidents.

Designed specifically for the Symfony ecosystem, Auditron provides fast, actionable security checks without requiring a running application.

## Features

Current inspections include:

| Check                              | Description                                                                                            |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------ |
| **Autoload Files**                 | Detects Composer autoloaded files that execute automatically and may introduce unnecessary risk.       |
| **Composer Security**              | Reviews Composer configuration for insecure settings and unsafe practices.                             |
| **CSRF Configuration**             | Ensures CSRF protection is enabled where appropriate.                                                  |
| **Environment Variable Security**  | Detects insecure handling of environment variables and sensitive configuration.                        |
| **Exception Leak Detection**       | Identifies configurations that may expose stack traces or internal application details.                |
| **File Permissions**               | Checks for insecure permissions on application files and directories.                                  |
| **Forbidden Functions**            | Detects usage of dangerous PHP functions such as `eval()`, `exec()`, `shell_exec()`, and similar APIs. |
| **.gitignore Security**            | Verifies that sensitive files are excluded from version control.                                       |
| **Hardcoded Secrets**              | Searches for API keys, passwords, tokens, private keys, and other embedded secrets.                    |
| **Insecure Deserialization**       | Detects potentially dangerous unserialization patterns.                                                |
| **Sensitive Information Exposure** | Finds files and configuration that may unintentionally expose sensitive data.                          |
| **Session Cookie Security**        | Verifies secure cookie flags such as `Secure`, `HttpOnly`, and `SameSite`.                             |
| **Weak Password Hashers**          | Detects insecure password hashing algorithms and outdated hasher configuration.                        |

Additional security checks will be added over time.

---

## Installation

Install via Composer:

```bash
composer require --dev corevitals/auditron
```

---

## Usage

Run Auditron from the root of your Symfony project:

```bash
php bin/auditron
```

Example:

```text
$ php bin/auditron

AUDITRON™ Security Inspection Unit v1.0

Scanning Symfony application...

✔ Composer Security
✔ CSRF Configuration
✔ Session Cookie Flags
⚠ Hardcoded Secrets
✔ Weak Password Hashers
✔ File Permissions

Scan completed.

13 checks performed
1 warning
0 critical issues
```

---

## Philosophy

Auditron focuses on practical security issues that are easy to overlook during development.

Rather than acting as a full-fledged static analyzer, it concentrates on Symfony-specific security best practices, secure configuration, and common application vulnerabilities.

The goal is simple:

> Find security problems before attackers do.

---

## Roadmap

Future inspections may include:

* Security headers
* Trusted proxies validation
* CORS configuration
* Doctrine entity security
* File upload validation
* Security voter analysis
* Firewall configuration auditing
* Access control verification
* Dependency vulnerability integration
* Secret manager detection
* Docker and container security
* CI/CD security validation

---

## Contributing

Contributions are welcome.

Ideas for additional security checks, bug reports, and pull requests are encouraged.

Each security check is implemented as an independent class, making it easy to extend Auditron with new inspections.

---

## License

MIT License.
