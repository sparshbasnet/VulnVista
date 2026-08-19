import { Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Evidence from "./pages/Evidence";
import Findings from "./pages/Findings";
import Scans from "./pages/Scans";
import Targets from "./pages/Targets";
import Login from "./pages/Login";
import ProtectedRoute from "./auth/ProtectedRoute";
import AdminRoute from "./auth/AdminRoute";
import Users from "./pages/Users";
import { AppDataProvider } from "./hooks/useAppData";

export default function App() {
  return (
    <Routes>
      <Route path="login" element={<Login />} />
      <Route element={<ProtectedRoute />}>
        <Route
          element={
            <AppDataProvider>
              <Layout />
            </AppDataProvider>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="targets" element={<Targets />} />
          <Route path="scans" element={<Scans />} />
          <Route path="findings" element={<Findings />} />
          <Route path="evidence" element={<Evidence />} />
          <Route element={<AdminRoute />}>
            <Route path="users" element={<Users />} />
          </Route>
        </Route>
      </Route>
    </Routes>
  );
}
