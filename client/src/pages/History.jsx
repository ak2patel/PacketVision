import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { HiOutlineClock, HiOutlineTrash, HiOutlineChartBar } from 'react-icons/hi';
import { getAnalyses } from '../services/api';
import api from '../services/api';

function History() {
  const [analyses, setAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAnalyses();
  }, []);

  const fetchAnalyses = async () => {
    try {
      const res = await getAnalyses();
      setAnalyses(res.data);
    } catch (err) {
      console.error('Failed to fetch analyses:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this analysis?')) return;
    try {
      await api.delete(`/analysis/${id}`);
      setAnalyses(prev => prev.filter(a => a._id !== id));
    } catch (err) {
      console.error('Failed to delete:', err);
    }
  };

  const formatSize = (bytes) => {
    if (!bytes) return '—';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  };

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Analysis History</h2>
        <p>View past analysis sessions and their results</p>
      </div>

      {loading ? (
        <div className="stats-grid">
          {[1, 2, 3].map(i => <div key={i} className="card"><div className="skeleton" style={{ height: 60 }} /></div>)}
        </div>
      ) : analyses.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon"><HiOutlineClock /></div>
          <h3>No Analyses Yet</h3>
          <p>Upload a .pcap file to get started.</p>
          <Link to="/" className="btn btn-primary" style={{ marginTop: 16 }}>Upload a File</Link>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {analyses.map((a) => (
            <div key={a._id} className="card" style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, marginBottom: 4 }}>{a.originalName}</div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', gap: 16 }}>
                  <span>{formatSize(a.fileSize)}</span>
                  <span>{a.stats?.totalPackets || 0} packets</span>
                  <span>{a.stats?.totalFlows || 0} flows</span>
                  <span>{new Date(a.createdAt).toLocaleString()}</span>
                </div>
              </div>
              <span className={`badge badge-${a.status === 'completed' ? 'green' : a.status === 'failed' ? 'red' : 'orange'}`}>
                {a.status}
              </span>
              {a.status === 'completed' && (
                <Link to={`/dashboard/${a._id}`} className="btn btn-sm btn-primary">
                  <HiOutlineChartBar /> View
                </Link>
              )}
              <button className="btn btn-sm btn-danger" onClick={() => handleDelete(a._id)}>
                <HiOutlineTrash />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default History;
