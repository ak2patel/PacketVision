# 🔍 PacketVision — Network Traffic Analyzer

A full-stack web application for analyzing network traffic from `.pcap` capture files. Uses Deep Packet Inspection (DPI) to identify applications, classify protocols, and visualize traffic patterns through an interactive dashboard.

## ✨ Features

- 📤 **Drag-and-drop** `.pcap` file upload
- 🔍 **Deep Packet Inspection** — TLS SNI extraction, HTTP Host detection
- 📊 **Interactive dashboard** — Application distribution, protocol breakdown, traffic timeline
- 📋 **Packet table** — Sortable, filterable, paginated view of all parsed packets
- 🚫 **Rule-based filtering** — Block traffic by IP, domain, or application
- 📥 **Filtered export** — Download a clean `.pcap` with blocked packets removed
- 🔄 **Real-time progress** — WebSocket-powered analysis updates

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React, Vite, ApexCharts, React Router |
| Backend | Node.js, Express |
| Database | MongoDB (local or Atlas) |
| Real-time | Socket.IO |
| File Upload | Multer |

## 🚀 Getting Started

### Prerequisites
- Node.js v18+
- MongoDB (local) or MongoDB Atlas account

### Installation

```bash
# Clone the repo
git clone <repo-url>
cd PacketVision

# Install all dependencies
npm run install-all

# Set up environment variables
cp server/.env.example server/.env
# Edit server/.env with your MongoDB URI

# Start development servers
npm run dev
```

### Environment Variables

Create `server/.env`:
```
PORT=5000
MONGO_URI=mongodb://localhost:27017/packetvision
# Or for Atlas:
# MONGO_URI=mongodb+srv://<user>:<password>@cluster.xxxxx.mongodb.net/packetvision
```

## 📸 Screenshots

*Coming soon after Day 4*

## 📁 Project Structure

```
PacketVision/
├── client/              # React frontend
│   ├── src/
│   │   ├── components/  # Reusable UI components
│   │   ├── pages/       # Route pages
│   │   ├── services/    # API client
│   │   └── App.jsx
│   └── package.json
├── server/              # Node.js backend
│   ├── config/          # Database config
│   ├── models/          # Mongoose schemas
│   ├── routes/          # API routes
│   ├── services/        # Core DPI logic
│   ├── middleware/       # File upload
│   └── server.js
├── .gitignore
├── package.json         # Root scripts
└── README.md
```

## 🤝 License

MIT
