# Motion Data - Static Multi-page Demo

This workspace contains a small multi-page static site (Home, Services, About, Contact) created from the HTML you provided.

Homepage filename
-----------------

The site's homepage is `index.html` located at the project root. The server (`server/index.js`) explicitly serves this file at `/` so make sure `index.html` remains present and is the primary entry for the site.

How to use

- Ensure the `assets/images` folder contains your images (filenames suggested in `assets/images/README.txt`).
- Open `index.html` in your browser (double-click or use Live Server in VS Code).

Firebase (optional) — quick setup
--------------------------------

If you want to enable Firebase Authentication (email/password) for the signup/login pages, follow these steps:

1. Create a Firebase project and register a Web app in the Firebase Console.
2. Enable Email/Password sign-in under Authentication -> Sign-in method.
3. Copy the Firebase config object from Project settings -> Your apps.
4. Create a file named `firebase-config.local.js` in the project root and paste the config as shown below:

```javascript
// firebase-config.local.js (local, do NOT commit)
window.firebaseConfig = {
	apiKey: "...",
	authDomain: "your-project-id.firebaseapp.com",
	projectId: "your-project-id",
	storageBucket: "your-project-id.appspot.com",
	messagingSenderId: "...",
	appId: "..."
};
```

5. Make sure `firebase-config.local.js` is listed in `.gitignore` (this repo includes a `.gitignore` with that entry). You can also rename and use `firebase-config.js` directly, but keep secrets out of version control.

6. Start the site (or open `signup.html`/`login.html`) and Firebase should initialize automatically. To confirm, open the browser console and run:

```javascript
window.firebaseHelpers.diagnostics()
```

Expected result: an object showing `sdkLoaded: true`, `configPresent: true`, and `initialized: true`.

If you prefer an example template, copy `firebase-config.local.example.js` to `firebase-config.local.js` and fill in the values.


What I added

- `index.html`, `services.html`, `about.html`, `contact.html` — separate pages with shared header/footer.
- `assets/css/styles.css` — upgraded advanced responsive styling and theme.
- `assets/js/script.js` and `assets/js/toast.js` — enhanced client-side behavior (mobile nav, FAQ accordion, testimonials, newsletter stub, contact form stub, toast notifications).
- `firebase-config.js` and `firebase-db.js` — stubs for Firebase integration (do not commit secrets to public repos).

New features added:
- Testimonials section on `index.html`.
- FAQ accordion on `index.html`.
- Pricing highlight cards on `services.html`.
- Newsletter subscription form (client-side stub) added to footers.
- Improved responsive and modern dark theme styling.

Next steps you may want me to do

- Wire the contact form to Firebase (I'll need your config or prefer server-side endpoint).
- Improve styles/look-and-feel and add images.
- Migrate to a templating approach (server-side includes or a simple build step) to avoid repeating header/footer.

Generating optimized image assets for the login/signup hero
--------------------------------------------------------

If you'd like to convert the SVG placeholders into production-ready JPEG and WebP images, use ImageMagick (magick) or Google's cwebp. Below are PowerShell-ready commands you can run from the project root. They convert the existing SVG placeholders into JPEG and WebP variants at three sizes (480, 768, 1200).

ImageMagick (recommended):

```powershell
# Convert SVG -> JPEG and WebP (change quality if needed)
magick assets/images/login-hero-480.svg -strip -resize 480x320 -quality 82 assets/images/login-hero-480.jpg
magick assets/images/login-hero-480.svg -strip -resize 480x320 -quality 80 assets/images/login-hero-480.webp

magick assets/images/login-hero-768.svg -strip -resize 768x512 -quality 82 assets/images/login-hero-768.jpg
magick assets/images/login-hero-768.svg -strip -resize 768x512 -quality 80 assets/images/login-hero-768.webp

magick assets/images/login-hero-1200.svg -strip -resize 1200x800 -quality 82 assets/images/login-hero-1200.jpg
magick assets/images/login-hero-1200.svg -strip -resize 1200x800 -quality 80 assets/images/login-hero-1200.webp
```

If you prefer using `cwebp` to encode WebP from an intermediate JPEG (optional):

```powershell
# Convert JPEG -> WebP with cwebp (quality 80)
cwebp -q 80 assets/images/login-hero-1200.jpg -o assets/images/login-hero-1200.webp
cwebp -q 80 assets/images/login-hero-768.jpg -o assets/images/login-hero-768.webp
cwebp -q 80 assets/images/login-hero-480.jpg -o assets/images/login-hero-480.webp
```

Quick tips
- Prefer WebP or AVIF for photos: they typically yield smaller files for equal quality.
- Keep the JPEGs for older browser fallbacks or tooling that doesn't support WebP.
- Test with Lighthouse or WebPageTest to verify savings and visual quality.

Repository essentials (recommended)
--------------------------------

Every repository benefits from these three files in its root:

- `README.md` — explains what the project is, how to run it, and any setup steps (you already have this file).
- `LICENSE` — an explicit license clarifies how others may use and contribute to your code. This repo includes an `MIT` license by default; change it if you prefer another license.
- `.gitignore` — prevents committing sensitive local files (example: `firebase-config.local.js`, `.env`, `node_modules/`, or local SSL certs).

I added `LICENSE` (MIT), a `.gitignore` entry, and `firebase-config.local.example.js` to help keep secrets out of version control. If you'd like a different license (Apache-2.0, GPLv3, etc.), tell me and I can swap it.


If you'd like, I can also add a small PowerShell script to automate these conversions and commit it to the repo.

Enabling HTTPS locally
----------------------

This project includes a small Node server in `server/index.js` that will serve the static site. The server now supports HTTPS when you provide a TLS key and certificate. If no cert/key are found it will fall back to HTTP as before.

How it works
- The server looks for `server/ssl/key.pem` and `server/ssl/cert.pem` by default.
- You can override paths with the environment variables `SSL_KEY_PATH` and `SSL_CERT_PATH`.
- Default ports: HTTP = `PORT` (defaults to `3000`), HTTPS = `HTTPS_PORT` (defaults to `8443`).
- When HTTPS is active the server also starts an HTTP listener that redirects traffic to the HTTPS port.

Generate local certs (recommended: mkcert)

mkcert is the easiest way to create locally-trusted certificates (Windows).

1. Install mkcert and nss/mkcert dependencies (follow mkcert docs).
2. From the project root run (PowerShell):

```powershell
# create server/ssl directory
mkdir server\ssl -Force
# generate cert for localhost
mkcert -key-file server\ssl\key.pem -cert-file server\ssl\cert.pem localhost 127.0.0.1 ::1
```

Now start the server (PowerShell):

```powershell
# npm start or node server\index.js (depending on your setup)
# you can set ports if you like:
$env:HTTPS_PORT=8443; $env:PORT=3000; node server\index.js
```

Alternative: create a self-signed cert with OpenSSL (not trusted by browsers without import)

```powershell
mkdir server\ssl -Force
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server\ssl\key.pem -out server\ssl\cert.pem -subj "/CN=localhost"
```

Notes
- Browsers will only show the site as fully secure if the certificate is trusted. Use mkcert for a better developer experience. For production, obtain certificates from a public CA (e.g., Let's Encrypt) and run the server on standard ports (80/443) or terminate TLS at a reverse proxy.
- Listening on port 443/80 requires elevated privileges on many systems; for local development we use non-privileged ports (8443/3000) by default.

