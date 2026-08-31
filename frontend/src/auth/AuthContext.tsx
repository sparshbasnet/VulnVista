import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { api } from "../services/api";
import type { User } from "../types";
import { AuthContext } from "./context";
import { UNAUTHORIZED_EVENT, clearToken, readToken, storeToken } from "./token";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const unauthorized = () => setUser(null);
    window.addEventListener(UNAUTHORIZED_EVENT, unauthorized);
    if (!readToken()) {
      setLoading(false);
    } else {
      api
        .me()
        .then(setUser)
        .catch(() => setUser(null))
        .finally(() => setLoading(false));
    }
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, unauthorized);
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const token = await api.login(username, password);
    storeToken(token.access_token);
    try {
      setUser(await api.me());
    } catch (error) {
      clearToken();
      throw error;
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      clearToken();
      setUser(null);
    }
  }, []);

  const changePassword = useCallback(
    async (currentPassword: string, newPassword: string) => {
      // The server revokes every token the old password authorized, so it hands
      // back a replacement to keep this tab signed in.
      const token = await api.changePassword(currentPassword, newPassword);
      storeToken(token.access_token);
      setUser(await api.me());
    },
    [],
  );

  const value = useMemo(
    () => ({
      user,
      loading,
      login,
      logout,
      changePassword,
      canOperate: user?.role === "ADMIN" || user?.role === "ANALYST",
      mustChangePassword: user?.must_change_password === true,
    }),
    [user, loading, login, logout, changePassword],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
