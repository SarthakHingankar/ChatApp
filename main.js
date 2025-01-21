const express = require("express");
const { createServer } = require("http");
const { Server } = require("socket.io");
const mysql = require("mysql2");
const path = require("path");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
require("dotenv").config();
const bcrypt = require("bcrypt");
const crypto = require("crypto");

const secretKey = process.env.msgSecret;
const secret = process.env.secretKey;
const algorithm = "aes-256-ctr";
const app = express();
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());
app.use(cookieParser());

const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  password: process.env.databasePassword,
  database: "users",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

const query = async (query, params) => {
  return new Promise((resolve, reject) => {
    pool.query(query, params, (error, results) => {
      if (error) {
        console.error("Database query error:", error.message);
        return reject(error);
      }
      resolve(results);
    });
  });
};

async function hashPass(password) {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
}

async function verifyPassword(inpass, pass) {
  return await bcrypt.compare(inpass, pass);
}

function encryptMessage(message) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
  let encrypted = cipher.update(message, "utf8", "hex");
  encrypted += cipher.final("hex");
  return {
    iv: iv.toString("hex"),
    encryptedData: encrypted,
  };
}

function decryptMessage(encryptedData, iv) {
  const decipher = crypto.createDecipheriv(
    algorithm,
    secretKey,
    Buffer.from(iv, "hex")
  );
  let decrypted = decipher.update(encryptedData, "hex", "utf-8");
  decrypted += decipher.final("utf-8");
  return decrypted;
}

const httpServer = createServer(app);
const io = new Server(httpServer);
const PORT = 3000;

app.get("/", (req, res) => {
  try {
    const token = req.cookies.authToken;
    if (!token) return res.redirect("/login");

    jwt.verify(token, secret, (err, decoded) => {
      if (err) return res.redirect("/login");
      return res.sendFile(path.join(__dirname, "public", "home.html"));
    });
  } catch (error) {
    console.error("Error in root route:", error.message);
    return res.status(500).send("Internal Server Error");
  }
});

app.get("/data", async (req, res) => {
  try {
    const token = req.cookies.authToken;
    const sender = req.headers.senders;
    const reciever = jwt.verify(token, secret);

    const msg = await query(`SELECT messages FROM uid WHERE username = ?`, [
      reciever,
    ]);
    const list = msg[0]?.messages || {};
    const messages = list[sender];

    if (messages) {
      const msgs = messages.map(({ iv, encryptedData }) =>
        decryptMessage(encryptedData, iv)
      );
      return res.json(msgs);
    } else {
      return res.status(404).json({ message: "No messages found" });
    }
  } catch (error) {
    console.error("Error in /data GET route:", error.message);
    return res.status(500).json({ message: "Server error" });
  }
});

app.post("/data", async (req, res) => {
  try {
    const token = req.cookies.authToken;
    const reciever = jwt.verify(token, secret);
    const sender = req.body.sender;

    const Query = `
      UPDATE uid
      SET messages = JSON_REMOVE(messages, ?)
      WHERE username = ?;
    `;
    const values = [`$.${sender}`, reciever];

    await query(Query, values);
    return res.status(200).json({ message: "Messages deleted successfully" });
  } catch (error) {
    console.error("Error in /data POST route:", error.message);
    return res.status(500).json({ message: "Server error" });
  }
});

app.get("/friends", async (req, res) => {
  try {
    const token = req.cookies.authToken;
    const user = jwt.verify(token, secret);
    const friends = await query(`SELECT friends FROM uid WHERE username = ?`, [
      user,
    ]);
    const friend = friends[0]?.friends || [];

    const unreadPromises = friend.map(async (friend) => {
      const unreadmsg = await query(
        `SELECT JSON_CONTAINS_PATH(messages, 'one', '$.${friend}') AS exist FROM uid WHERE username = ?`,
        [user]
      );
      if (unreadmsg[0]?.exist) return friend;
    });

    const unreads = (await Promise.all(unreadPromises)).filter(Boolean);
    return res.json({ friend, unreads });
  } catch (error) {
    console.error("Error in /friends GET route:", error.message);
    return res.status(500).json({ message: "Server error" });
  }
});

app.post("/friends", async (req, res) => {
  try {
    const friend = req.body.contactName;
    const user = jwt.verify(req.cookies.authToken, secret);

    const exists = await query(
      `SELECT EXISTS(SELECT 1 FROM uid WHERE username = ?) AS user_exists;`,
      [friend]
    );

    if (exists[0]?.user_exists) {
      await query(
        `UPDATE uid SET friends = JSON_ARRAY_APPEND(friends, '$', ?) WHERE username = ?`,
        [friend, user]
      );
      return res.status(200).json({ message: "Friend added successfully" });
    } else {
      return res.status(404).json({ message: "Friend not found" });
    }
  } catch (error) {
    console.error("Error in /friends POST route:", error.message);
    return res.status(500).json({ message: "Server error" });
  }
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await query(`SELECT password FROM uid WHERE username = ?`, [
      username,
    ]);

    if (!user[0]) {
      return res.redirect("/signup");
    }

    const isValidPassword = await verifyPassword(password, user[0].password);

    if (isValidPassword) {
      const token = jwt.sign(username, secret);
      res.cookie("authToken", token, {
        httpOnly: true,
        secure: false,
        maxAge: 3600000,
      });
      return res.redirect("/");
    } else {
      return res.status(401).send("Invalid credentials");
    }
  } catch (error) {
    console.error("Error in /login POST route:", error.message);
    return res.status(500).json({ message: "Server error" });
  }
});

app.get("/signup", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "signup.html"));
});

app.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hashedPassword = await hashPass(password);

    await query(
      `INSERT INTO uid (username, email, password, friends, messages) VALUES (?, ?, ?, '[]', '{}')`,
      [username, email, hashedPassword]
    );

    return res.redirect("/login");
  } catch (error) {
    console.error("Error in /signup POST route:", error.message);
    return res.status(500).json({ message: "Server error" });
  }
});

const userSocketMap = new Map();

io.use((socket, next) => {
  try {
    const cookies = socket.handshake.headers.cookie;
    if (cookies) {
      const auth = cookies
        .split("; ")
        .find((c) => c.startsWith("authToken="))
        ?.split("=")[1];
      const uid = jwt.verify(auth, secret);
      userSocketMap.set(uid, socket.id);
      next();
    } else {
      throw new Error("Authentication token not found");
    }
  } catch (error) {
    console.error("Socket authentication error:", error.message);
    next(new Error("Unauthorized"));
  }
});

io.on("connection", async (socket) => {
  try {
    socket.on("message", async ({ reciever, message }) => {
      try {
        const msg = encryptMessage(message);

        // Extract sender from cookies
        const cookies = socket.handshake.headers.cookie;
        if (!cookies) {
          throw new Error("Missing cookies in handshake headers.");
        }

        const auth = cookies
          .split("; ")
          .find((c) => c.startsWith("authToken="))
          ?.split("=")[1];

        if (!auth) {
          throw new Error("Missing authToken cookie.");
        }

        const sender = jwt.verify(auth, secret, (err, decoded) => {
          if (err) {
            throw new Error("Invalid authToken.");
          }
          return decoded;
        });

        if (!sender) {
          throw new Error("Sender not found.");
        }

        // Update the messages in the database
        const path = `$.${sender}`;
        const queryUpdateMessages = `
          UPDATE uid
          SET messages = CASE
              WHEN JSON_CONTAINS_PATH(messages, 'one', '${path}') THEN 
                  JSON_ARRAY_APPEND(messages, '${path}', JSON_OBJECT("iv", "${msg.iv}", "encryptedData", "${msg.encryptedData}"))
              ELSE 
                  JSON_SET(messages, '${path}', JSON_ARRAY(JSON_OBJECT("iv", "${msg.iv}", "encryptedData", "${msg.encryptedData}")))
          END
          WHERE username = '${reciever}';
        `;

        await query(queryUpdateMessages);

        // Check if the recipient is connected and emit the message
        const recipientSocketId = userSocketMap.get(reciever);
        if (recipientSocketId) {
          io.to(recipientSocketId).emit("message", { sender, message });
        }
      } catch (error) {
        console.error("Error handling 'message' event:", error.message);
        socket.emit("error", { message: "Failed to send message." });
      }
    });

    socket.on("disconnect", () => {
      try {
        // Remove the disconnected user from the map
        for (let [uid, socketId] of userSocketMap.entries()) {
          if (socketId === socket.id) {
            userSocketMap.delete(uid);
            break;
          }
        }
      } catch (error) {
        console.error("Error during disconnect cleanup:", error.message);
      }
    });
  } catch (error) {
    console.error("Error during connection initialization:", error.message);
    socket.emit("error", { message: "Connection error occurred." });
  }
});
