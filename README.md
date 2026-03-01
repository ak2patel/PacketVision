# 🔍 PacketVision — Network Traffic Analyzer

<div align="center">

**A full-stack web application for analyzing network traffic from `.pcap` capture files**

Built with React • Node.js • Express • MongoDB

[![License: MIT](https://img.shields.io/badge/License-MIT-06d6a0.svg)](LICENSE)

</div>

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 📤 **Drag-and-drop Upload** | Upload `.pcap` / `.pcapng` files up to 50MB |
| 🔍 **Deep Packet Inspection** | TLS SNI extraction, HTTP Host detection, DNS query parsing |
| 📊 **Interactive Dashboard** | Donut, bar, and area charts powered by ApexCharts |
| 📋 **Packet Table** | Sortable, filterable, paginated view of all parsed packets |
| 🚫 **Block Rules** | Create rules to filter by IP address, domain, or application |
| 📥 **Filtered Export** | Download a clean `.pcap` with blocked packets removed |
| 🔄 **Real-time Progress** | Socket.IO-powered live analysis updates |
| 🌐 **App Classification** | Identifies 25+ services (Google, YouTube, Netflix, etc.) |
| 📜 **Analysis History** | Browse and manage past analysis sessions |

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 19, Vite, ApexCharts, React Router, React Icons |
| Backend | Node.js, Express |
| Database | MongoDB (local or Atlas) |
| Real-time | Socket.IO |
| File Upload | Multer |
| HTTP Client | Axios |

## 🚀 Getting Started

### Prerequisites

- **Node.js** v18+
- **MongoDB** — local install or [MongoDB Atlas](https://www.mongodb.com/atlas) account

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/ak2patel/PacketVision.git
cd PacketVision

# 2. Install server dependencies
cd server && npm install && cd ..

# 3. Install client dependencies
cd client && npm install && cd ..

# 4. Configure environment
cp server/.env.example server/.env
# Edit server/.env with your MongoDB URI
```

### Running the Application

```bash
# Terminal 1 — Start the backend
cd server && npm run dev

# Terminal 2 — Start the frontend
cd client && npm run dev
```

Then open **http://localhost:5173** in your browser.

### Environment Variables

Create `server/.env`:

```env
PORT=5000

# Local MongoDB
MONGO_URI=mongodb://localhost:27017/packetvision

# OR MongoDB Atlas
# MONGO_URI=mongodb+srv://<user>:<password>@cluster0.xxxxx.mongodb.net/packetvision?retryWrites=true&w=majority

MAX_FILE_SIZE=50
```

## 📁 Project Structure

```
PacketVision/
├── client/                       # React frontend (Vite)
│   ├── src/
│   │   ├── components/
│   │   │   ├── PacketTable.jsx   # Sortable/filterable packet table
│   │   │   └── PacketTable.css
│   │   ├── pages/
│   │   │   ├── Upload.jsx        # File upload with drag-and-drop
│   │   │   ├── Dashboard.jsx     # Charts and analysis results
│   │   │   ├── Rules.jsx         # Block rule management
│   │   │   └── History.jsx       # Past analysis sessions
│   │   ├── services/
│   │   │   └── api.js            # Axios API client
│   │   ├── App.jsx               # Router + sidebar layout
│   │   └── index.css             # Design system (dark theme)
│   └── package.json
├── server/                       # Node.js backend
│   ├── config/
│   │   └── db.js                 # Mongoose connection
│   ├── models/
│   │   ├── Analysis.js           # Analysis schema
│   │   └── BlockRule.js          # Block rule schema
│   ├── routes/
│   │   ├── analysis.js           # Upload, list, detail, export, delete
│   │   └── rules.js              # CRUD for block rules
│   ├── services/
│   │   ├── pcapParser.js         # Binary PCAP file reader/writer
│   │   ├── packetParser.js       # Ethernet/IPv4/TCP/UDP parser
│   │   ├── dpiEngine.js          # SNI + HTTP Host + DNS extraction
│   │   └── analysisService.js    # Pipeline orchestrator
│   ├── middleware/
│   │   └── upload.js             # Multer file upload config
│   ├── uploads/                  # Uploaded .pcap files
│   ├── server.js                 # Express + Socket.IO entry point
│   └── package.json
├── .gitignore
├── package.json
└── README.md
```

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/analysis/upload` | Upload a .pcap file and start analysis |
| `GET` | `/api/analysis` | List all analyses |
| `GET` | `/api/analysis/:id` | Get full analysis details |
| `GET` | `/api/analysis/:id/export` | Download filtered .pcap |
| `DELETE` | `/api/analysis/:id` | Delete an analysis |
| `GET` | `/api/rules` | List all block rules |
| `POST` | `/api/rules` | Create a block rule |
| `PUT` | `/api/rules/:id` | Update a block rule |
| `DELETE` | `/api/rules/:id` | Delete a block rule |
| `GET` | `/api/health` | Health check |

## 🔬 How DPI Works

PacketVision implements Deep Packet Inspection in three layers:

1. **PCAP Parser** — Reads the binary PCAP file format, handling byte-order detection
2. **Protocol Parser** — Dissects Ethernet → IPv4 → TCP/UDP headers, extracting IPs, ports, flags
3. **DPI Engine** — Inspects application-layer payloads:
   - **TLS**: Parses Client Hello to extract SNI (Server Name Indication)
   - **HTTP**: Extracts the `Host:` header from requests
   - **DNS**: Decodes queried domain names
   - **Classification**: Maps domains to 25+ known applications

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

MIT
