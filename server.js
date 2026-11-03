require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const cors = require('cors');

const app = express();

// Webhook ke liye raw body capture karna zaroori hai
app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf;
    }
}));
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

// 1. Register API (HWID optional/placeholder support)
app.post('/api/register', async (req, res) => {
    const { email, password, hwid } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, message: "Missing required fields" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        // Website se register hone par agar HWID WEB_ hai ya null hai toh use accept karega
        const clientHwid = hwid || null;

        const result = await pool.query(
            `INSERT INTO users (email, password, hwid) VALUES ($1, $2, $3) RETURNING id, email`,
            [email.toLowerCase(), hashedPassword, clientHwid]
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

// 2. Login & Single-Device HWID Verification (Website Account Auto-Link to PC HWID)
app.post('/api/login', async (req, res) => {
    const { email, password, hwid } = req.body;
    if (!email || !password) {
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

        // AGAR ACCOUNT WEBSITE SE BANA HO (WEB_...) YA NULL HO, TOH ASLI PC HWID LINK KAR DEIN
        if (hwid && (!user.hwid || user.hwid.startsWith("WEB_"))) {
            await pool.query(`UPDATE users SET hwid = $1 WHERE id = $2`, [hwid, user.id]);
            user.hwid = hwid;
        } else if (hwid && user.hwid && user.hwid !== hwid) {
            // Agar pehle se kisi doosre real PC par locked hai
            return res.status(403).json({ 
                success: false, 
                message: "Ye account kisi doosre PC par registered hai. HWID mismatch!" 
            });
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
        if (user.hwid && user.hwid !== hwid) {
            return res.json({ is_premium: false, plan: "free", speed_limit_mb: 2, max_concurrent: 3 });
        }

        if (user.is_premium) {
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
            expiryDate.setDate(expiryDate.getDate() + 30);
        } else if (plan === 'lifetime') {
            expiryDate.setDate(expiryDate.getDate() + 36500);
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

// 6. Razorpay Webhook Endpoint (Automatic Background Activation)
app.post('/api/payment/webhook', async (req, res) => {
    const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;
    const signature = req.headers['x-razorpay-signature'];

    if (webhookSecret && signature) {
        const expectedSignature = crypto
            .createHmac('sha256', webhookSecret)
            .update(req.rawBody)
            .digest('hex');

        if (expectedSignature !== signature) {
            return res.status(400).json({ status: 'invalid signature' });
        }
    }

    const event = req.body.event;

    if (event === 'payment.captured' || event === 'order.paid') {
        const payment = req.body.payload.payment.entity;
        const orderId = payment.order_id;
        const customerEmail = (payment.email || '').toLowerCase();

        try {
            let plan = 'monthly';
            let expiryDate = new Date();
            if (payment.amount >= 15000) {
                plan = 'lifetime';
                expiryDate.setDate(expiryDate.getDate() + 36500);
            } else {
                expiryDate.setDate(expiryDate.getDate() + 30);
            }

            if (customerEmail) {
                await pool.query(
                    `UPDATE users SET is_premium = TRUE, plan_type = $1, premium_expiry = $2 WHERE email = $3`,
                    [plan, expiryDate.toISOString(), customerEmail]
                );
            }

            if (orderId) {
                await pool.query(
                    `UPDATE orders SET payment_id = $1, status = 'paid' WHERE order_id = $2`,
                    [payment.id, orderId]
                );
            }
        } catch (dbErr) {
            console.error("Webhook DB Update Error:", dbErr);
        }
    }

    res.json({ status: 'ok' });
});

// 7. Auto-Update Version Checker Endpoint
app.get('/api/version', (req, res) => {
    res.json({
        version: "1.0.1",
        download_url: "https://drive.google.com/file/d/1xUPZyE810tua8qCBQfsLj70yE-1zguoT/view?usp=sharing",
        changelog: "First official release with Pro features & high-speed downloads."
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
