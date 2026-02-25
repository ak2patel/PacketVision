import { useCallback, useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { useNavigate } from 'react-router-dom';
import { HiOutlineUpload, HiOutlineDocumentText } from 'react-icons/hi';
import './Upload.css';

function Upload() {
  const navigate = useNavigate();
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);

  const onDrop = useCallback((acceptedFiles) => {
    if (acceptedFiles.length > 0) {
      setFile(acceptedFiles[0]);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/octet-stream': ['.pcap', '.pcapng'],
    },
    maxFiles: 1,
    maxSize: 50 * 1024 * 1024, // 50MB
  });

  const handleUpload = async () => {
    if (!file) return;

    setUploading(true);
    setProgress(0);

    // Simulated progress — will be replaced with real API call in Day 3
    const interval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 95) {
          clearInterval(interval);
          return prev;
        }
        return prev + Math.random() * 15;
      });
    }, 300);

    // TODO: Replace with real API call
    setTimeout(() => {
      clearInterval(interval);
      setProgress(100);
      setTimeout(() => {
        setUploading(false);
        // navigate(`/dashboard/${analysisId}`);
      }, 500);
    }, 3000);
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  };

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Upload & Analyze</h2>
        <p>Upload a .pcap capture file to analyze network traffic</p>
      </div>

      {/* Dropzone */}
      <div
        {...getRootProps()}
        className={`dropzone ${isDragActive ? 'active' : ''}`}
      >
        <input {...getInputProps()} />
        <div className="dropzone-icon">📁</div>
        <h3>
          {isDragActive
            ? 'Drop the file here...'
            : 'Drag & drop a .pcap file here'}
        </h3>
        <p>or click to browse • Max 50MB • .pcap / .pcapng</p>
      </div>

      {/* Selected File */}
      {file && (
        <div className="selected-file card" style={{ marginTop: '20px' }}>
          <div className="file-info">
            <HiOutlineDocumentText className="file-icon" />
            <div className="file-details">
              <span className="file-name">{file.name}</span>
              <span className="file-size">{formatFileSize(file.size)}</span>
            </div>
            <button
              className="btn btn-primary"
              onClick={handleUpload}
              disabled={uploading}
            >
              <HiOutlineUpload />
              {uploading ? 'Analyzing...' : 'Analyze'}
            </button>
          </div>

          {/* Progress Bar */}
          {uploading && (
            <div className="progress-container">
              <div className="progress-bar">
                <div
                  className="progress-fill"
                  style={{ width: `${Math.min(progress, 100)}%` }}
                />
              </div>
              <span className="progress-text">
                {Math.round(Math.min(progress, 100))}%
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default Upload;
