import { AuthProvider, useAuth } from "./auth";
import { Layout } from "./Layout";
import { RouterProvider, useRouter } from "./router";
import { ThemeProvider } from "./theme";
import { LoginPage } from "./pages/Login";
import { NodesPage } from "./pages/Nodes";
import { MyDevicesPage } from "./pages/MyDevices";
import { UsersPage } from "./pages/Users";
import { SettingsPage } from "./pages/Settings";
import { RegisterPage } from "./pages/Register";
import { ACLPage } from "./pages/ACL";
import { DNSPage } from "./pages/DNS";
import { LogsPage } from "./pages/Logs";
import { ServicesPage } from "./pages/Services";
import { DocsPage } from "./pages/Docs";
import { DebugPage } from "./pages/Debug";

const BASE = "/admin";

function AuthGuard({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const { path } = useRouter();

  if (loading) {
    return (
      <div style={{ display: "flex", justifyContent: "center", alignItems: "center", minHeight: "100vh" }}>
        <span className="spinner" />
      </div>
    );
  }

  if (!user) {
    // Use location.replace to avoid building up history entries.
    // Only pass returnTo if we're not already on the login page.
    if (!path.startsWith(`${BASE}/login`)) {
      window.location.replace(`${BASE}/login?returnTo=${encodeURIComponent(path)}`);
    }
    return null;
  }

  return <>{children}</>;
}

function Router() {
  const { path } = useRouter();
  const { user } = useAuth();

  // Members see a simplified "My Devices" view
  if (user?.role === "member") {
    switch (path) {
      case `${BASE}/docs`:
        return <DocsPage />;
      default:
        return <MyDevicesPage />;
    }
  }

  switch (path) {
    case `${BASE}/users`:
      return <UsersPage />;
    case `${BASE}/acls`:
      return <ACLPage />;
    case `${BASE}/dns`:
      return <DNSPage />;
    case `${BASE}/services`:
      return <ServicesPage />;
    case `${BASE}/settings`:
      return <SettingsPage />;
    case `${BASE}/logs`:
      return <LogsPage />;
    case `${BASE}/debug`:
      return <DebugPage />;
    case `${BASE}/docs`:
      return <DocsPage />;
    default:
      return <NodesPage />;
  }
}

function AppContent() {
  const { loading } = useAuth();
  const { path, navigate } = useRouter();

  // Redirect bare /admin or /admin/ to /admin/machines
  if (path === BASE || path === `${BASE}/`) {
    navigate(`${BASE}/machines`);
    return null;
  }

  // Login route — no auth required
  if (path === `${BASE}/login`) {
    if (loading) {
      return (
        <div style={{ display: "flex", justifyContent: "center", alignItems: "center", minHeight: "100vh" }}>
          <span className="spinner" />
        </div>
      );
    }
    return <LoginPage />;
  }

  // Registration page — standalone (no admin Layout)
  const registerMatch = path.match(/^\/admin\/register\/(.+)$/);
  if (registerMatch) {
    return (
      <AuthGuard>
        <RegisterPage authId={registerMatch[1]} />
      </AuthGuard>
    );
  }

  // All other routes require authentication
  return (
    <AuthGuard>
      <Layout>
        <Router />
      </Layout>
    </AuthGuard>
  );
}

export function App() {
  return (
    <ThemeProvider>
      <RouterProvider>
        <AuthProvider>
          <AppContent />
        </AuthProvider>
      </RouterProvider>
    </ThemeProvider>
  );
}
