import { Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import Account from "./pages/Account";
import Dashboard from "./pages/Dashboard";
import Evidence from "./pages/Evidence";
import Findings from "./pages/Findings";
import ForcedPasswordChange from "./pages/ForcedPasswordChange";
import ForgotPassword from "./pages/ForgotPassword";
import Login from "./pages/Login";
import ResetPassword from "./pages/ResetPassword";
import Scans from "./pages/Scans";
import Targets from "./pages/Targets";
import Users from "./pages/Users";
import ProtectedRoute from "./auth/ProtectedRoute";
import AdminRoute from "./auth/AdminRoute";
import { AppDataProvider } from "./hooks/useAppData";

export default function App() {
  return (
    <Routes>
      <Route path="login" element={<Login />} />
      <Route path="forgot-password" element={<ForgotPassword />} />
      <Route path="reset-password" element={<ResetPassword />} />
      <Route element={<ProtectedRoute />}>
        {/* Outside the app chrome: the backend blocks every other route until the
            administrator-issued password has been replaced. */}
        <Route path="change-password" element={<ForcedPasswordChange />} />
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
          <Route path="account" element={<Account />} />
          <Route element={<AdminRoute />}>
            <Route path="users" element={<Users />} />
          </Route>
        </Route>
      </Route>
    </Routes>
  );
}
