# SSO Automation Toolkit

A local, web-based toolkit for parsing SAML metadata and generating ready-to-use
SSO configuration for **Auth0** and **customer identity providers**.

This tool is designed to eliminate repetitive manual SSO setup steps by
automatically extracting endpoints, certificates, and identifiers from SAML
metadata and presenting them in a copy-paste-ready format.

> Built as a real-world internal tooling project use.

---

##  Features

### Identity Provider → Auth0 Configuration
- Parse SAML metadata from:
  - Remote metadata URLs
  - Uploaded XML files
- Automatically extract:
  - Sign In URL (SSO)
  - Sign Out URL (SLO)
  - Entity ID / Issuer
  - X509 Signing Certificate
- Convert certificates to **PEM format**
- Detect common IdPs (Okta, Microsoft Entra ID)
- Generate editable **Auth0-ready attribute mappings**
- Warn about missing fields and certificate expiration

### Service Provider → Customer Setup
- Generate customer-facing SSO setup packs including:
  - Metadata URL
  - Entity ID
  - ACS / Reply URL
  - Sign-in landing page
- Supports multiple environments (e.g. prod / staging)
- Output formatted for easy copy/paste or download

### General
- Runs entirely **locally**
- No data persistence
- No external services required
- Designed for clarity, safety, and speed

---

##  Tech Stack

- **Node.js** (Express)
- **JavaScript**
- **fast-xml-parser** (SAML XML parsing)
- **Multer** (secure file uploads)
- **HTML / CSS**


<img width="1134" height="902" alt="image" src="https://github.com/user-attachments/assets/bd4bcdee-31ae-4f91-9a30-db676b4f621f" />




---

##  Getting Started

### Prerequisites
- Node.js v18 or newer

### Installation

```bash
npm install
