import { Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import Threats from './pages/Threats'
import Analytics from './pages/Analytics'
import LiveScanner from './pages/LiveScanner'
import RedTeam from './pages/RedTeam'
import Policies from './pages/Policies'
import Settings from './pages/Settings'
import AgentAnalysis from './pages/AgentAnalysis'

export default function App() {
  return (
    <div className="flex h-screen overflow-hidden bg-slate-950">
      {/* Sidebar */}
      <Sidebar />

      {/* Main content */}
      <main className="flex-1 ml-64 overflow-y-auto">
        <div className="p-8 min-h-full">
          <Routes>
            <Route path="/"          element={<Dashboard />} />
            <Route path="/agent"     element={<AgentAnalysis />} />
            <Route path="/threats"   element={<Threats />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/scanner"   element={<LiveScanner />} />
            <Route path="/redteam"   element={<RedTeam />} />
            <Route path="/policies"  element={<Policies />} />
            <Route path="/settings"  element={<Settings />} />
          </Routes>
        </div>
      </main>
    </div>
  )
}
