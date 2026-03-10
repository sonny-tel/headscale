import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";
import {
  type User,
  validateSession,
  logout as apiLogout,
  getSessionToken,
} from "./api";

interface AuthState {
  user: User | null;
  loading: boolean;
  error: string | null;
}

interface AuthContextType extends AuthState {
  setUser: (user: User) => void;
  logout: () => Promise<void>;
  checkSession: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    user: null,
    loading: true,
    error: null,
  });

  const checkSession = useCallback(async () => {
    const token = getSessionToken();
    if (!token) {
      setState({ user: null, loading: false, error: null });
      return;
    }

    try {
      const user = await validateSession();
      setState({ user, loading: false, error: null });
    } catch {
      setState({ user: null, loading: false, error: null });
    }
  }, []);

  useEffect(() => {
    checkSession();
  }, [checkSession]);

  const setUser = useCallback((user: User) => {
    setState({ user, loading: false, error: null });
  }, []);

  const logout = useCallback(async () => {
    await apiLogout();
    setState({ user: null, loading: false, error: null });
    window.location.href = "/admin/login";
  }, []);

  return (
    <AuthContext.Provider
      value={{ ...state, setUser, logout, checkSession }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return ctx;
}
