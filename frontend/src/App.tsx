import { Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Evidence from "./pages/Evidence";
import Findings from "./pages/Findings";
import Scans from "./pages/Scans";
import Targets from "./pages/Targets";
import { AppDataProvider } from "./hooks/useAppData";

export default function App() {
  return (
    <AppDataProvider>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="targets" element={<Targets />} />
          <Route path="scans" element={<Scans />} />
          <Route path="findings" element={<Findings />} />
          <Route path="evidence" element={<Evidence />} />
        </Route>
      </Routes>
    </AppDataProvider>
  );
}
