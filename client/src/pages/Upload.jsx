import { useCallback, useState, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';
import { useNavigate } from 'react-router-dom';
import { HiOutlineUpload, HiOutlineDocumentText, HiOutlineCheckCircle, HiOutlineExclamationCircle } from 'react-icons/hi';
import { uploadPcap } from '../services/api';
import { io } from 'socket.io-client';
import './Upload.css';

const SOCKET_URL = import.meta.env.VITE_SOCKET_URL || 'http://localhost:5000';

function Upload() {
  const navigate = useNavigate();
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [statusMsg, setStatusMsg] = useState('');
  const [analysisId, setAnalysisId] = useState(null);
  const [error, setError] = useState(null);
  const [completed, setCompleted] = useState(false);

  // Socket.IO — listen for analysis progress
  useEffect(() => {
    if (!analysisId) return;

    const socket = io(SOCKET_URL);

    socket.on('analysis:progress', (data) => {
      if (data.analysisId !== analysisId) return;

      setProgress(data.progress);
      setStatusMsg(data.message);

      if (data.status === 'completed') {
        setCompleted(true);
        setUploading(false);
        // Auto-navigate after a short delay
        setTimeout(() => {
          navigate(`/dashboard/${analysisId}`);
        }, 1500);
      }

      if (data.status === 'failed') {
        setError(data.message);
        setUploading(false);
      }
    });

    return () => socket.disconnect();
  }, [analysisId, navigate]);

  const onDrop = useCallback((acceptedFiles) => {
    if (acceptedFiles.length > 0) {
      setFile(acceptedFiles[0]);
      setError(null);
      setCompleted(false);
      setProgress(0);
      setStatusMsg('');
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/octet-stream': ['.pcap', '.pcapng'],
    },
    maxFiles: 1,
    maxSize: 50 * 1024 * 1024,
  });

  const handleUpload = async () => {
    if (!file) return;

    setUploading(true);
    setProgress(0);
    setError(null);
    setCompleted(false);
    setStatusMsg('Uploading file...');

    try {
      const response = await uploadPcap(file, (uploadProgress) => {
        // During upload phase, show 0-10% progress
        setProgress(Math.min(uploadProgress * 0.1, 10));
      });

      setAnalysisId(response.data.analysisId);
      setStatusMsg('File uploaded. Starting analysis...');
    } catch (err) {
      const msg = err.response?.data?.error || err.message || 'Upload failed';
      setError(msg);
      setUploading(false);
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  };

  const resetUpload = () => {
    setFile(null);
    setUploading(false);
    setProgress(0);
    setStatusMsg('');
    setAnalysisId(null);
    setError(null);
    setCompleted(false);
  };

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Upload & Analyze</h2>
        <p>Upload a .pcap capture file to analyze network traffic</p>
      </div>

      {/* Dropzone */}
      {!uploading && !completed && (
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
      )}

      {/* Selected File & Progress */}
      {file && (
        <div className="selected-file card" style={{ marginTop: '20px' }}>
          <div className="file-info">
            <HiOutlineDocumentText className="file-icon" />
            <div className="file-details">
              <span className="file-name">{file.name}</span>
              <span className="file-size">{formatFileSize(file.size)}</span>
            </div>
            {!uploading && !completed && (
              <button
                className="btn btn-primary"
                onClick={handleUpload}
              >
                <HiOutlineUpload />
                Analyze
              </button>
            )}
          </div>

          {/* Progress Bar */}
          {(uploading || completed) && (
            <div className="progress-section">
              <div className="progress-container">
                <div className="progress-bar">
                  <div
                    className={`progress-fill ${completed ? 'completed' : ''}`}
                    style={{ width: `${Math.min(progress, 100)}%` }}
                  />
                </div>
                <span className="progress-text">
                  {Math.round(Math.min(progress, 100))}%
                </span>
              </div>
              <div className="progress-status">
                {completed ? (
                  <span className="status-success">
                    <HiOutlineCheckCircle /> Analysis complete! Redirecting to dashboard...
                  </span>
                ) : (
                  <span className="status-active">{statusMsg}</span>
                )}
              </div>
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="upload-error">
              <HiOutlineExclamationCircle />
              <span>{error}</span>
              <button className="btn btn-sm btn-secondary" onClick={resetUpload}>
                Try Again
              </button>
            </div>
          )}
        </div>
      )}

      {/* Recent tip */}
      <div className="upload-tip card" style={{ marginTop: '24px' }}>
        <h3>💡 Getting a .pcap file</h3>
        <p>You can capture network traffic using <strong>Wireshark</strong> or <strong>tcpdump</strong>, 
           or use the sample <code>test_dpi.pcap</code> file from the project.</p>
      </div>
    </div>
  );
}

export default Upload;
