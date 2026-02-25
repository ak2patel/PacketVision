import { BrowserRouter as Router, Routes, Route, NavLink } from 'react-router-dom';
import { HiOutlineUpload, HiOutlineChartBar, HiOutlineShieldCheck, HiOutlineClock } from 'react-icons/hi';
import Upload from './pages/Upload';
import Dashboard from './pages/Dashboard';
import Rules from './pages/Rules';
import History from './pages/History';
import './App.css';

function App() {
  return (
    <Router>
      <div className="app-layout">
        {/* Sidebar */}
        <aside className="sidebar">
          <div className="sidebar-logo">
            <div className="logo-icon">PV</div>
            <div>
              <h1>PacketVision</h1>
            </div>
            <span className="version">v1.0</span>
          </div>

          <nav className="sidebar-nav">
            <span className="nav-section-label">Analysis</span>

            <NavLink
              to="/"
              end
              className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
            >
              <span className="icon"><HiOutlineUpload /></span>
              Upload & Analyze
            </NavLink>

            <NavLink
              to="/dashboard"
              className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
            >
              <span className="icon"><HiOutlineChartBar /></span>
              Dashboard
            </NavLink>

            <span className="nav-section-label">Management</span>

            <NavLink
              to="/rules"
              className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
            >
              <span className="icon"><HiOutlineShieldCheck /></span>
              Block Rules
            </NavLink>

            <NavLink
              to="/history"
              className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
            >
              <span className="icon"><HiOutlineClock /></span>
              History
            </NavLink>
          </nav>

          <div className="sidebar-footer">
            <p>Built with MERN Stack</p>
          </div>
        </aside>

        {/* Main Content */}
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Upload />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/dashboard/:id" element={<Dashboard />} />
            <Route path="/rules" element={<Rules />} />
            <Route path="/history" element={<History />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
