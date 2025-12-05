# Admin Dashboard - Backend Connection Guide

## Setup Complete! ✅

Your admin dashboard is now connected to a backend data system.

## What Was Added:

### 1. Data Storage (`server/data.json`)
- JSON-based database for storing orders, customers, packages, and stats
- Sample data pre-loaded for testing

### 2. API Endpoints (`server/index.js`)
The following API endpoints were added:

- **GET /api/stats** - Get dashboard statistics
- **GET /api/orders** - Get all orders (with filtering, search, pagination)
- **GET /api/orders/:id** - Get single order details
- **POST /api/orders** - Create new order
- **PUT /api/orders/:id** - Update order
- **DELETE /api/orders/:id** - Delete order
- **GET /api/customers** - Get all customers
- **GET /api/packages** - Get all packages
- **GET /api/packages/top** - Get top selling packages

### 3. Frontend Integration (`assets/js/admin.js`)
- Automatic data loading from API
- Live filtering and search
- Real-time stats updates
- CRUD operations for orders

## How to Use:

### Start the Server:
```powershell
cd server
npm install  # If you haven't already
node index.js
```

The server will start on `http://localhost:3000`

### Access Admin Dashboard:
Open your browser and go to:
```
http://localhost:3000/admin.html
```

## Features Now Working:

✅ **Dashboard Stats** - Shows real order count, revenue, customers, success rate
✅ **Recent Orders** - Displays last 5 orders from database
✅ **Top Packages** - Calculates best-selling packages from order data
✅ **Order Management** - Filter, search, view, edit, and delete orders
✅ **Pagination** - Browse through all orders with page navigation
✅ **Real-time Updates** - Changes reflect immediately

## Adding New Orders:

Orders can be added via:

1. **Through your order pages** (order-mtn.html, etc.) - modify them to send orders to `/api/orders`
2. **Directly in data.json** - manually add order objects
3. **Via API** - POST requests to `/api/orders`

Example POST request:
```javascript
fetch('http://localhost:3000/api/orders', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    customer: 'Test User',
    phone: '0241234567',
    email: 'test@email.com',
    package: 'MTN 10GB',
    network: 'MTN',
    amount: 45.00
  })
});
```

## Next Steps:

1. **Integrate order forms** - Connect order-mtn.html, order-telecel.html, etc. to POST to `/api/orders`
2. **Add authentication** - Protect admin routes with login
3. **Upgrade to real database** - Replace data.json with MongoDB, PostgreSQL, etc.
4. **Add email notifications** - Send emails when orders are created/completed
5. **Add analytics charts** - Visualize data with Chart.js or similar

## Troubleshooting:

**If data doesn't load:**
1. Make sure the server is running
2. Check browser console for errors (F12)
3. Verify `server/data.json` exists and is valid JSON
4. Check server terminal for error messages

**To reset data:**
- Edit `server/data.json` and restart the server

Enjoy your modern admin dashboard! 🚀
