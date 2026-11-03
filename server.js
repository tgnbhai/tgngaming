require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Supabase PostgreSQL Pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Auto-create database tables
const initDB = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                hwid TEXT DEFAULT NULL,
                is_premium BOOLEAN DEFAULT FALSE,
                premium_expiry TIMESTAMP DEFAULT NULL,
                plan_type TEXT DEFAULT 'free',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS orders (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                order_id TEXT,
                payment_id TEXT,
                amount INTEGER,
                plan TEXT,
                status TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log("PostgreSQL Database & Tables Ready.");
    } catch (err) {
        console.error("DB Init Error:", err);
    }
};
initDB();

const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID || 'dummy',
    key_secret: process.env.RAZORPAY_KEY_SECRET || 'dummy'
});

app.get('/', (req, res) => {
    res.send("TGN License Server is Running Live 24/7!");
});

// 1. Register API
app.post('/api/register', async (req, res) => {
    const { email, password, hwid } = req.body;
    if (!email || !password || !hwid) {
        return res.status(400).json({ success: false, message: "Missing required fields" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            `INSERT INTO users (email, password, hwid) VALUES ($1, $2, $3) RETURNING id, email`,
            [email.toLowerCase(), hashedPassword, hwid]
        );
        const user = result.rows[0];
        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET);
        res.json({ success: true, token, message: "Registered successfully" });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ success: false, message: "Email already registered" });
        }
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// 2. Login & Single-Device HWID Verification
app.post('/api/login', async (req, res) => {
    const { email, password, hwid } = req.body;
    if (!email || !password || !hwid) {
        return res.status(400).json({ success: false, message: "Missing fields" });
    }

    try {
        const result = await pool.query(`SELECT * FROM users WHERE email = $1`, [email.toLowerCase()]);
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: "Invalid password" });
        }

        if (user.hwid && user.hwid !== hwid) {
            return res.status(403).json({ 
                success: false, 
                message: "Ye account kisi doosre PC par registered hai. HWID mismatch!" 
            });
        }

        if (!user.hwid) {
            await pool.query(`UPDATE users SET hwid = $1 WHERE id = $2`, [hwid, user.id]);
        }

        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET);
        res.json({ success: true, token, is_premium: user.is_premium, plan: user.plan_type });
    } catch {
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// 3. License Status Check (Auto-Expires 30 Days Monthly Plan)
app.post('/api/license-status', async (req, res) => {
    const { token, hwid } = req.body;
    if (!token || !hwid) {
        return res.json({ is_premium: false, plan: "free", speed_limit_mb: 2, max_concurrent: 3 });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const result = await pool.query(`SELECT * FROM users WHERE id = $1`, [decoded.id]);
        if (result.rows.length === 0) {
            return res.json({ is_premium: false, plan: "free", speed_limit_mb: 2, max_concurrent: 3 });
        }

        const user = result.rows[0];
        if (user.hwid !== hwid) {
            return res.json({ is_premium: false, plan: "free", speed_limit_mb: 2, max_concurrent: 3 });
        }

        if (user.is_premium) {
            // Agar plan monthly hai aur 30 din nikal chuke hain -> revert to free
            if (user.plan_type !== 'lifetime' && new Date(user.premium_expiry) < new Date()) {
                await pool.query(`UPDATE users SET is_premium = FALSE, plan_type = 'free' WHERE id = $1`, [user.id]);
                return res.json({ is_premium: false, plan: "free", speed_limit_mb: 2, max_concurrent: 3 });
            }

            return res.json({ 
                is_premium: true, 
                plan: user.plan_type, 
                expiry: user.premium_expiry,
                speed_limit_mb: 0,
                max_concurrent: 99
            });
        }

        res.json({ is_premium: false, plan: "free", speed_limit_mb: 2, max_concurrent: 3 });
    } catch {
        res.json({ is_premium: false, plan: "free", speed_limit_mb: 2, max_concurrent: 3 });
    }
});

// 4. Create Order
app.post('/api/create-order', async (req, res) => {
    const { token, plan } = req.body;
    if (!token) return res.status(401).json({ success: false, message: "Login required" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        let amount = 0;
        if (plan === 'monthly') amount = 59 * 100;
        else if (plan === 'lifetime') amount = 150 * 100;
        else return res.status(400).json({ success: false, message: "Invalid plan" });

        const options = {
            amount: amount,
            currency: "INR",
            receipt: `rcpt_${decoded.id}_${Date.now()}`
        };

        const order = await razorpay.orders.create(options);
        await pool.query(
            `INSERT INTO orders (user_id, order_id, amount, plan, status) VALUES ($1, $2, $3, $4, 'created')`,
            [decoded.id, order.id, amount / 100, plan]
        );

        res.json({ success: true, order, key_id: process.env.RAZORPAY_KEY_ID });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// 5. Verify Payment
app.post('/api/verify-payment', async (req, res) => {
    const { token, razorpay_order_id, razorpay_payment_id, razorpay_signature, plan } = req.body;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const body = razorpay_order_id + "|" + razorpay_payment_id;
        const expectedSignature = crypto
            .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
            .update(body.toString())
            .digest('hex');

        if (expectedSignature !== razorpay_signature) {
            return res.status(400).json({ success: false, message: "Payment verification failed" });
        }

        let expiryDate = new Date();
        if (plan === 'monthly') {
            expiryDate.setDate(expiryDate.getDate() + 30); // 30 Days Expiry Set
        } else if (plan === 'lifetime') {
            expiryDate.setDate(expiryDate.getDate() + 36500); // 100 Years
        }

        await pool.query(
            `UPDATE users SET is_premium = TRUE, plan_type = $1, premium_expiry = $2 WHERE id = $3`,
            [plan, expiryDate.toISOString(), decoded.id]
        );

        await pool.query(
            `UPDATE orders SET payment_id = $1, status = 'paid' WHERE order_id = $2`,
            [razorpay_payment_id, razorpay_order_id]
        );

        res.json({ success: true, message: "Premium Activated Successfully!" });
    } catch {
        res.status(500).json({ success: false, message: "Verification error" });
    }
});

// Hosted Browser Checkout View
app.get('/checkout', (req, res) => {
    const { order_id, plan, token } = req.query;
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>TGN Downloader Payment</title>
        </head>
        <body style="background:#0f172a;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:sans-serif;">
            <div style="text-align:center;background:#1e293b;padding:36px;border-radius:12px;border:1px solid #334155;max-width:380px;width:90%;">
                <h2 style="margin:0 0 8px 0;color:#38bdf8;">TGN Downloader Pro</h2>
                <p style="color:#94a3b8;margin-bottom:24px;">Upgrade Plan: <b>${(plan || '').toUpperCase()}</b></p>
                <button id="payBtn" style="width:100%;padding:14px;background:#38bdf8;color:#0f172a;font-weight:bold;border:none;border-radius:8px;font-size:16px;cursor:pointer;">Proceed to Pay</button>
            </div>
            <script src="https://checkout.razorpay.com/v1/checkout.js"></script>
            <script>
                document.getElementById('payBtn').onclick = function() {
                    var options = {
                        "key": "${process.env.RAZORPAY_KEY_ID}",
                        "order_id": "${order_id}",
                        "name": "TGN Downloader",
                        "description": "${plan} License",
                        "handler": function (response){
                            fetch('/api/verify-payment', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({
                                    token: "${token}",
                                    plan: "${plan}",
                                    razorpay_order_id: response.razorpay_order_id,
                                    razorpay_payment_id: response.razorpay_payment_id,
                                    razorpay_signature: response.razorpay_signature
                                })
                            }).then(r => r.json()).then(data => {
                                alert(data.message);
                                window.close();
                            });
                        }
                    };
                    var rzp = new Razorpay(options);
                    rzp.open();
                }
                window.onload = () => document.getElementById('payBtn').click();
            </script>
        </body>
        </html>
    `);
});

// 6. Auto-Update Version Checker Endpoint
app.get('/api/version', (req, res) => {
    res.json({
        version: "1.0.2",
        download_url: "https://drive.google.com/file/d/1xUPZyE810tua8qCBQfsLj70yE-1zguoT/view?usp=sharing",
        changelog: "First official release with Pro features & high-speed downloads."
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
