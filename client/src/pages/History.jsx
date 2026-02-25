import { HiOutlineClock } from 'react-icons/hi';

function History() {
  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Analysis History</h2>
        <p>View past analysis sessions and their results</p>
      </div>

      <div className="empty-state">
        <div className="empty-icon"><HiOutlineClock /></div>
        <h3>No Previous Analyses</h3>
        <p>Your past analysis sessions will appear here. Upload a .pcap file to get started.</p>
      </div>
    </div>
  );
}

export default History;
