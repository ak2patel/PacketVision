import { HiOutlineChartBar } from 'react-icons/hi';

function Dashboard() {
  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Dashboard</h2>
        <p>Visualize your network traffic analysis results</p>
      </div>

      <div className="empty-state">
        <div className="empty-icon"><HiOutlineChartBar /></div>
        <h3>No Analysis Yet</h3>
        <p>Upload a .pcap file to see traffic analysis, application breakdown, and protocol distribution charts.</p>
      </div>
    </div>
  );
}

export default Dashboard;
