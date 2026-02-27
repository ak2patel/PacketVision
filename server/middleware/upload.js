const multer = require('multer');
const path = require('path');

// Configure storage — save uploaded .pcap files to server/uploads/
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, '..', 'uploads'));
  },
  filename: (req, file, cb) => {
    // Unique filename: timestamp-originalname
    const uniqueName = `${Date.now()}-${file.originalname}`;
    cb(null, uniqueName);
  },
});

// File filter — only accept .pcap and .pcapng
const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  if (ext === '.pcap' || ext === '.pcapng') {
    cb(null, true);
  } else {
    cb(new Error('Only .pcap and .pcapng files are allowed'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: (process.env.MAX_FILE_SIZE || 50) * 1024 * 1024, // Default 50MB
  },
});

module.exports = upload;
