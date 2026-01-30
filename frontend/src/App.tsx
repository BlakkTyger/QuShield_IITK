import { Routes, Route, Navigate } from 'react-router-dom';

// Layout & Auth
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';

// Pages
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import DashboardPage from './pages/DashboardPage';
import InventoryPage from './pages/InventoryPage';
import DiscoveryPage from './pages/DiscoveryPage';
import CBOMPage from './pages/CBOMPage';
import PosturePage from './pages/PosturePage';
import RatingPage from './pages/RatingPage';
import ReportsPage from './pages/ReportsPage';
import ScansPage from './pages/ScansPage';

function App() {
  return (
    <Routes>
      {/* Public Routes */}
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      
      {/* Protected Routes */}
      <Route 
        path="/" 
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="inventory" element={<InventoryPage />} />
        <Route path="discovery" element={<DiscoveryPage />} />
        <Route path="cbom" element={<CBOMPage />} />
        <Route path="posture" element={<PosturePage />} />
        <Route path="rating" element={<RatingPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="scans" element={<ScansPage />} />
      </Route>

      {/* Fallback */}
      <Route path="*" element={<Navigate to="/login" replace />} />
    </Routes>
  );
}

export default App;
