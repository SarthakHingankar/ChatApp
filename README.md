# Real-Time Messaging Platform

Backend platform enabling low-latency messaging with persistent chat history, authenticated users, and encrypted message storage.

---

## Overview

This project demonstrates the backend architecture of a real-time messaging system built using Express, Socket.IO, and MySQL. It supports authenticated user sessions, instant message delivery, encrypted message persistence, and offline message synchronization.

Messages are transmitted in real time when recipients are online and securely stored for later retrieval when they are offline.

---

## Highlights

- Real-time messaging using WebSockets
- JWT-based authentication with secure HTTP cookies
- AES-256 encrypted message storage
- Persistent chat history using MySQL JSON columns
- Offline message delivery
- Online user tracking through socket management

---

## Architecture

```
                Browser
                    │
           HTTP + WebSocket
                    │
             Express Server
                    │
        JWT Authentication Layer
                    │
             Socket.IO Gateway
                    │
        In-Memory User Registry
                    │
      Message Encryption Layer
                    │
               MySQL Database
```

---

## Tech Stack

### Backend

- Node.js
- Express
- Socket.IO

### Database

- MySQL

### Security

- JWT Authentication
- bcrypt
- AES-256 Encryption

---

## Features

### Authentication

- User registration
- Secure password hashing
- JWT-based login
- Cookie authentication

---

### Real-Time Messaging

Users communicate through persistent WebSocket connections managed by Socket.IO.

Messages are instantly delivered when recipients are online.

---

### Offline Messaging

If a recipient is offline, encrypted messages are stored in the database and delivered when they reconnect.

---

### Message Encryption

Every message is encrypted before being written to the database using AES-256 encryption.

Only decrypted messages are returned to authenticated users.

---

### Contact Management

Users can:

- Add contacts
- View friend list
- Track unread conversations

---

## Message Flow

```
Sender
   │
   ▼
Socket.IO Event
   │
Encrypt Message
   │
Store in MySQL
   │
Recipient Online?
   │
 ┌─Yes──────────────┐
 │                  │
 ▼                  ▼
Deliver         Store Only
Immediately
```

---

## Engineering Decisions

### WebSockets

Socket.IO provides persistent bidirectional communication, enabling low-latency message delivery without polling.

---

### JWT Authentication

Authentication is performed once during connection establishment, allowing WebSocket events to be associated with authenticated users.

---

### Message Encryption

Messages are encrypted before persistence to prevent storing plaintext conversations in the database.

---

### User Presence

Connected users are tracked through an in-memory socket registry, allowing direct message delivery without additional database lookups.

---

### Persistent Storage

Messages remain available after users disconnect, enabling offline synchronization when they reconnect.

---

## Running Locally

### Prerequisites

- Node.js
- MySQL

Install dependencies

```bash
npm install
```

Configure environment variables

```
DATABASE_PASSWORD=...
SECRET_KEY=...
MSG_SECRET=...
```

Start the server

```bash
npm start
```

---

## Future Improvements

- Group conversations
- Typing indicators
- Read receipts
- File sharing
- Message search
- Horizontal scaling with Redis Adapter
- End-to-end encryption
- Media attachments

---

## License

This project is intended for learning and demonstration purposes.
