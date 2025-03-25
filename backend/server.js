const express = require("express");
const mysql = require("mysql2/promise");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const SECRET_KEY = "ursecretkey"; // Ganti dengan secret yang lebih aman

app.use(cors({
    origin: "https://torn.velobytes.net",
    credentials: true
}));

app.use(express.json());

// Konfigurasi Database
const dbConfig = {
    host: process.env.MYSQL_HOST || "mysql",
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE,
};

// **LOGIN - AUTENTIKASI API KEY**
app.post("/torn/login", async (req, res) => {
    const { apiKey } = req.body;

    if (!apiKey) {
        return res.status(400).json({ error: "API Key is required" });
    }

    try {
        const response = await axios.get(
            `https://api.torn.com/user/?selections=basic&key=${apiKey}`
        );

        if (response.data.error) {
            return res.status(400).json({ error: "Invalid API Key" });
        }

        const tornId = response.data.player_id;
        const username = response.data.name;

        const conn = await mysql.createConnection(dbConfig);

        const [rows] = await conn.execute(
            "SELECT * FROM users WHERE torn_id = ?",
            [tornId]
        );

        if (rows.length === 0) {
            await conn.execute("INSERT INTO users (torn_id, username, apiKey) VALUES (?, ?, ?)", [
                tornId, username, apiKey,
            ]);
        } else {
            await conn.execute("UPDATE users SET apiKey = ? WHERE torn_id = ?", [
                apiKey, tornId,
            ]);
        }

        conn.end();

        // **Buat JWT Token**
        const token = jwt.sign({ tornId, username }, SECRET_KEY, { expiresIn: "1h" });

        res.json({ message: "Login successful", token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// **MIDDLEWARE CEK JWT**
function verifyToken(req, res, next) {
    const token = req.headers["authorization"];

    if (!token) {
        return res.status(403).json({ error: "No token provided" });
    }

    jwt.verify(token.split(" ")[1], SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: "Unauthorized" });
        }
        req.user = decoded;
        next();
    });
}

// **CEK PROFIL USER (HANYA JIKA LOGIN)**
app.get("/torn/account", verifyToken, async (req, res) => {
    const tornId = req.user.tornId;

    const conn = await mysql.createConnection(dbConfig);
    const [rows] = await conn.execute("SELECT * FROM users WHERE torn_id = ?", [tornId]);
    conn.end();

    if (rows.length === 0) {
        return res.status(404).json({ error: "User not found" });
    }

    res.json({ user: rows[0] });
});

app.listen(3000, () => {
    console.log("Backend running on port 3000");
});
