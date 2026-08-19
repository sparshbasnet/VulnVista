import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { api } from "../services/api";
import type { User } from "../types";
import { AuthContext } from "./context";
const TOKEN_KEY = "vulnvista_access_token";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const unauthorized = () => setUser(null);
    window.addEventListener("vulnvista:unauthorized", unauthorized);
    const token = sessionStorage.getItem(TOKEN_KEY);
    if (!token) {
      setLoading(false);
    } else {
      api.me().then(setUser).catch(() => setUser(null)).finally(() => setLoading(false));
    }
    return () => window.removeEventListener("vulnvista:unauthorized", unauthorized);
  }, []);

  async function login(username: string, password: string) {
    const token = await api.login(username, password);
    sessionStorage.setItem(TOKEN_KEY, token.access_token);
    try {
      setUser(await api.me());
    } catch (error) {
      sessionStorage.removeItem(TOKEN_KEY);
      throw error;
    }
  }

  async function logout() {
    try {
      await api.logout();
    } finally {
      sessionStorage.removeItem(TOKEN_KEY);
      setUser(null);
    }
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        login,
        logout,
        canOperate: user?.role === "ADMIN" || user?.role === "ANALYST",
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
