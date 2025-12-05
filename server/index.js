const express = require('express');
const fetch = require('node-fetch');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
require('dotenv').config();

const app = express();
// Ports: HTTP defaults to 3000 (or PORT), HTTPS defaults to 8443 (or HTTPS_PORT)
const PORT = process.env.PORT || 3000;
const HTTPS_PORT = process.env.HTTPS_PORT || 8443;
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY || process.env.PAYSTACK_SECRET;

if (!PAYSTACK_SECRET) {
  console.warn('Warning: PAYSTACK_SECRET_KEY not set. Verification will fail until you set it in .env');
}

const cors = require('cors');
app.use(cors());

// Redirect root to /index.html so the browser URL shows the homepage filename
app.get('/', (req, res) => {
  // 301 permanent redirect to the explicit index file
  res.redirect(301, '/index.html');
});

// Serve the static site (project root parent of server folder)
app.use(express.static(path.join(__dirname, '..')));

// JSON body for /verify
app.use(express.json());

// Load data from JSON file
const dataPath = path.join(__dirname, 'data.json');
function loadData() {
  try {
    const data = fs.readFileSync(dataPath, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error('Error loading data:', err);
    return { orders: [], customers: [], packages: [], stats: {} };
  }
}

function saveData(data) {
  try {
    fs.writeFileSync(dataPath, JSON.stringify(data, null, 2));
    return true;
  } catch (err) {
    console.error('Error saving data:', err);
    return false;
  }
}

// API Endpoints for Admin Dashboard

// Get dashboard stats
app.get('/api/stats', (req, res) => {
  const data = loadData();
  res.json(data.stats || {});
});

// Get all orders with filtering and pagination
app.get('/api/orders', (req, res) => {
  const data = loadData();
  let orders = data.orders || [];
  
  // Filter by status
  if (req.query.status && req.query.status !== 'All Status') {
    orders = orders.filter(o => o.status.toLowerCase() === req.query.status.toLowerCase());
  }
  
  // Filter by network
  if (req.query.network && req.query.network !== 'All Networks') {
    orders = orders.filter(o => o.network === req.query.network);
  }
  
  // Search
  if (req.query.search) {
    const search = req.query.search.toLowerCase();
    orders = orders.filter(o => 
      o.id.toLowerCase().includes(search) ||
      o.customer.toLowerCase().includes(search) ||
      o.phone.includes(search) ||
      o.package.toLowerCase().includes(search)
    );
  }
  
  // Pagination
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const startIndex = (page - 1) * limit;
  const endIndex = page * limit;
  
  const paginatedOrders = orders.slice(startIndex, endIndex);
  
  res.json({
    orders: paginatedOrders,
    total: orders.length,
    page: page,
    totalPages: Math.ceil(orders.length / limit)
  });
});

// Get single order
app.get('/api/orders/:id', (req, res) => {
  const data = loadData();
  const order = data.orders.find(o => o.id === req.params.id);
  if (order) {
    res.json(order);
  } else {
    res.status(404).json({ error: 'Order not found' });
  }
});

// Create new order
app.post('/api/orders', (req, res) => {
  const data = loadData();
  const newOrder = {
    id: `ORD-${Date.now()}`,
    date: new Date().toISOString(),
    ...req.body,
    status: req.body.status || 'pending'
  };
  data.orders.unshift(newOrder);
  if (saveData(data)) {
    res.status(201).json(newOrder);
  } else {
    res.status(500).json({ error: 'Failed to save order' });
  }
});

// Update order
app.put('/api/orders/:id', (req, res) => {
  const data = loadData();
  const index = data.orders.findIndex(o => o.id === req.params.id);
  if (index !== -1) {
    data.orders[index] = { ...data.orders[index], ...req.body };
    if (saveData(data)) {
      res.json(data.orders[index]);
    } else {
      res.status(500).json({ error: 'Failed to update order' });
    }
  } else {
    res.status(404).json({ error: 'Order not found' });
  }
});

// Delete order
app.delete('/api/orders/:id', (req, res) => {
  const data = loadData();
  const index = data.orders.findIndex(o => o.id === req.params.id);
  if (index !== -1) {
    data.orders.splice(index, 1);
    if (saveData(data)) {
      res.json({ message: 'Order deleted' });
    } else {
      res.status(500).json({ error: 'Failed to delete order' });
    }
  } else {
    res.status(404).json({ error: 'Order not found' });
  }
});

// Get all customers
app.get('/api/customers', (req, res) => {
  const data = loadData();
  res.json(data.customers || []);
});

// Get all packages
app.get('/api/packages', (req, res) => {
  const data = loadData();
  res.json(data.packages || []);
});

// Get packages
app.get('/api/packages', (req, res) => {
    const data = readData();
    res.json(data.packages || []);
});

// Get top packages
app.get('/api/packages/top', (req, res) => {
  const data = loadData();
  const orders = data.orders || [];
  
  // Count sales per package
  const packageSales = {};
  orders.forEach(order => {
    if (order.status === 'completed') {
      if (!packageSales[order.package]) {
        packageSales[order.package] = {
          name: order.package,
          network: order.network,
          sales: 0,
          revenue: 0
        };
      }
      packageSales[order.package].sales++;
      packageSales[order.package].revenue += order.amount;
    }
  });
  
  // Convert to array and sort by sales
  const topPackages = Object.values(packageSales)
    .sort((a, b) => b.sales - a.sales)
    .slice(0, 5);
  
  res.json(topPackages);
});

// Verify endpoint: server-side verify a Paystack transaction by reference
app.get('/verify', async (req, res) => {
  const reference = req.query.reference;
  if (!reference) return res.status(400).json({ error: 'Missing reference' });
  if (!PAYSTACK_SECRET) return res.status(500).json({ error: 'Server not configured with Paystack secret' });

  try {
    const url = 'https://api.paystack.co/transaction/verify/' + encodeURIComponent(reference);
    const r = await fetch(url, { headers: { Authorization: 'Bearer ' + PAYSTACK_SECRET } });
    const data = await r.json();
    if (!r.ok) return res.status(r.status).json({ error: data });
    // You can perform additional checks here (amount, currency, metadata) before accepting
    res.json(data);
  } catch (err) {
    console.error('Error verifying reference', err);
    res.status(500).json({ error: 'Verification failed', detail: err.message });
  }
});

// Webhook endpoint: raw body required to validate signature
app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['x-paystack-signature'] || req.headers['paystack-signature'];
  if (!PAYSTACK_SECRET) {
    console.warn('Webhook received but PAYSTACK_SECRET_KEY not set');
    return res.sendStatus(400);
  }
  const hash = crypto.createHmac('sha512', PAYSTACK_SECRET).update(req.body).digest('hex');
  if (hash !== sig) {
    console.warn('Invalid webhook signature');
    return res.sendStatus(400);
  }

  // Parse JSON body
  let event;
  try { event = JSON.parse(req.body.toString()); } catch (e) { event = null; }

  // Handle event (you can extend this to persist order state)
  console.log('Received Paystack webhook event:', event?.event);

  // ACK
  res.sendStatus(200);
});

// Helper to start HTTP server (optionally redirecting to HTTPS)
function startHttpServer(redirectToHttps) {
  const server = http.createServer((req, res) => {
    if (redirectToHttps) {
      // Build host without port and redirect to HTTPS port
      const hostHeader = req.headers.host || 'localhost';
      const host = hostHeader.split(':')[0];
      const location = `https://${host}:${HTTPS_PORT}${req.url}`;
      res.writeHead(301, { Location: location });
      res.end();
      return;
    }

    // If not redirecting, let Express handle the request
    app(req, res);
  });

  server.listen(PORT, () => {
    console.log(`Motion Data server running on http://localhost:${PORT}`);
  });
}

// Try to load SSL cert + key from env or default `server/ssl/` directory.
// Support three options (in order): mkcert/OpenSSL PEM files (key+cert), a PFX bundle (cert.pfx),
// or fall back to HTTP if none found.
const sslKeyPath = process.env.SSL_KEY_PATH || path.join(__dirname, 'ssl', 'key.pem');
const sslCertPath = process.env.SSL_CERT_PATH || path.join(__dirname, 'ssl', 'cert.pem');
const sslPfxPath = process.env.SSL_PFX_PATH || path.join(__dirname, 'ssl', 'cert.pfx');
const sslPfxPass = process.env.SSL_PFX_PASS || '';

if (fs.existsSync(sslKeyPath) && fs.existsSync(sslCertPath)) {
  try {
    const key = fs.readFileSync(sslKeyPath);
    const cert = fs.readFileSync(sslCertPath);
    const httpsServer = https.createServer({ key, cert }, app);

    httpsServer.listen(HTTPS_PORT, () => {
      console.log(`Motion Data HTTPS server running on https://localhost:${HTTPS_PORT}`);
    });

    // Also start HTTP that redirects to HTTPS (useful for browsers)
    startHttpServer(true);
    console.log(`HTTP -> HTTPS redirect enabled on http://localhost:${PORT}`);
  } catch (err) {
    console.error('Failed to start HTTPS server with key/cert, falling back to HTTP. Error:', err);
    startHttpServer(false);
  }
} else if (fs.existsSync(sslPfxPath)) {
  try {
    const pfx = fs.readFileSync(sslPfxPath);
    const opts = { pfx };
    if (sslPfxPass) opts.passphrase = sslPfxPass;

    const httpsServer = https.createServer(opts, app);
    httpsServer.listen(HTTPS_PORT, () => {
      console.log(`Motion Data HTTPS server running (PFX) on https://localhost:${HTTPS_PORT}`);
    });

    // Also start HTTP that redirects to HTTPS (useful for browsers)
    startHttpServer(true);
    console.log(`HTTP -> HTTPS redirect enabled on http://localhost:${PORT}`);
  } catch (err) {
    console.error('Failed to start HTTPS server with PFX, falling back to HTTP. Error:', err);
    startHttpServer(false);
  }
} else {
  console.warn('SSL key/cert not found. To enable HTTPS place `key.pem` and `cert.pem` in `server/ssl/`, place a PFX as `server/ssl/cert.pfx`, or set SSL_KEY_PATH / SSL_CERT_PATH / SSL_PFX_PATH env vars.');
  console.warn(`Looking for key: ${sslKeyPath}`);
  console.warn(`Looking for cert: ${sslCertPath}`);
  console.warn(`Looking for pfx: ${sslPfxPath}`);
  startHttpServer(false);
}
