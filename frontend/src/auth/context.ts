import { createContext } from "react";
import type { User } from "../types";

export interface AuthState {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  /** Change your own password. Rotates the session token, so you stay signed in. */
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  canOperate: boolean;
  /** True while the account is on an administrator-issued temporary password. */
  mustChangePassword: boolean;
}

export const AuthContext = createContext<AuthState | null>(null);
