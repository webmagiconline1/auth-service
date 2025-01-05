const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const fetch = require('node-fetch');
const path = require('path');

const app = express();
const port = 80;

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

const users = []; // This should be replaced with a database in a real application

const verifyRecaptcha = async (token) => {
    const secretKey = 'YOUR_SECRET_KEY';
    const response = await fetch(`https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${token}`, {
        method: 'POST'
    });
    const data = await response.json();
    return data.success;
};

// Register a new user
app.post('/register', async (req, res) => {
    const { username, password, recaptchaToken } = req.body;
    const isHuman = await verifyRecaptcha(recaptchaToken);
    if (!isHuman) {
        return res.status(400).send('reCAPTCHA verification failed');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    res.status(201).send('User registered');
});

// Login a user
app.post('/login', async (req, res) => {
    const { username, password, recaptchaToken } = req.body;
    const isHuman = await verifyRecaptcha(recaptchaToken);
    if (!isHuman) {
        return res.status(400).send('reCAPTCHA verification failed');
    }
    const user = users.find(u => u.username === username);
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ username }, 'secret_key', { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).send('Invalid credentials');
    }
});

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, 'secret_key', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Protected route
app.get('/profile', authenticateToken, (req, res) => {
    res.json({ message: `Welcome ${req.user.username}` });
});

app.listen(port, () => {
    console.log(`Authentication service running on port ${port}`);
});