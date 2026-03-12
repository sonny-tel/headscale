import { useState, useEffect, useRef, type FormEvent } from "react";
import { useAuth } from "../auth";
import {
  loginWithPassword,
  verifyOTP,
  getGitHubAuthURL,
  gitHubCallback,
  getAuthMethods,
  checkApprovalStatus,
  type AuthMethods,
} from "../api";

const RETURN_TO_COOKIE = "hs_returnTo";
const RETURN_TO_LS_KEY = "hs_login_returnTo";

/** Detect GitHub callback params synchronously before first render. */
const INITIAL_HAS_CALLBACK = (() => {
  const params = new URLSearchParams(window.location.search);
  return !!(params.get("code") && params.get("state"));
})();

/** Read returnTo from all available sources (cookie > localStorage > URL). */
function getReturnTo(): string {
  // 1. Cookie — most reliable across mobile cross-origin redirects
  const cookieMatch = document.cookie
    .split("; ")
    .find((c) => c.startsWith(RETURN_TO_COOKIE + "="));
  if (cookieMatch) {
    const val = decodeURIComponent(cookieMatch.split("=")[1]);
    if (val.startsWith("/")) return val;
  }
  // 2. localStorage — survives tab/context switches
  try {
    const stored = localStorage.getItem(RETURN_TO_LS_KEY);
    if (stored && stored.startsWith("/")) return stored;
  } catch { /* private browsing may throw */ }
  // 3. URL query param
  const params = new URLSearchParams(window.location.search);
  const val = params.get("returnTo");
  // Only allow relative paths to prevent open redirect
  if (val && val.startsWith("/")) return val;
  return "/admin/machines";
}

/** Persist returnTo in cookie + localStorage so it survives the OAuth redirect. */
function saveReturnTo(returnTo: string) {
  const secure = window.location.protocol === "https:" ? "; Secure" : "";
  document.cookie = `${RETURN_TO_COOKIE}=${encodeURIComponent(returnTo)}; path=/; max-age=600; SameSite=Lax${secure}`;
  try { localStorage.setItem(RETURN_TO_LS_KEY, returnTo); } catch { /* ignore */ }
}

/** Clear the persisted returnTo from all storage. */
function clearReturnTo() {
  document.cookie = `${RETURN_TO_COOKIE}=; path=/; max-age=0`;
  try { localStorage.removeItem(RETURN_TO_LS_KEY); } catch { /* ignore */ }
}

function isRegistrationReturn(returnTo: string): boolean {
  return /^\/admin\/register\//.test(returnTo);
}

function navigateAfterLogin(returnTo: string) {
  clearReturnTo();
  window.location.href = returnTo;
}

export function LoginPage() {
  const { user, setUser } = useAuth();
  const [methods, setMethods] = useState<AuthMethods | null>(null);
  const [showLocalLogin, setShowLocalLogin] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [otpCode, setOtpCode] = useState("");
  const [needsOTP, setNeedsOTP] = useState(false);
  const [error, setError] = useState("");
  const [pendingApproval, setPendingApproval] = useState(false);
  const [pendingUsername, setPendingUsername] = useState("");
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);

  // Whether we're processing a GitHub OAuth callback return.
  // Starts true if the URL had code+state on mount.
  const [processingCallback, setProcessingCallback] = useState(INITIAL_HAS_CALLBACK);

  // Capture returnTo once on mount so it's stable even after URL cleanup.
  const returnToRef = useRef(getReturnTo());
  const returnTo = returnToRef.current;
  const isRegistration = isRegistrationReturn(returnTo);

  // If already logged in AND we're not mid-callback, redirect immediately.
  useEffect(() => {
    if (user && !processingCallback) navigateAfterLogin(returnTo);
  }, [user, returnTo, processingCallback]);

  useEffect(() => {
    getAuthMethods()
      .then((m) => {
        setMethods(m);
        if (m.local_auth_enabled && !m.github_auth_enabled) {
          setShowLocalLogin(true);
        }
      })
      .catch(() => {
        setMethods({ local_auth_enabled: true, github_auth_enabled: false });
        setShowLocalLogin(true);
      });
  }, []);

  // Handle the GitHub OAuth callback — extract code/state, exchange them,
  // then navigate to the stored returnTo destination.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    if (!code || !state) return;

    // Strip the OAuth params from the URL so a refresh won't replay them.
    window.history.replaceState({}, "", "/admin/login");

    setLoading(true);
    gitHubCallback(code, state)
      .then((resp) => {
        setUser(resp.user);
        setProcessingCallback(false);
        navigateAfterLogin(returnTo);
      })
      .catch((err) => {
        const msg = String(err.message || err);
        const pendingMatch = msg.match(/pending_approval:(\S+)/);
        if (pendingMatch) {
          setPendingUsername(pendingMatch[1]);
          setPendingApproval(true);
          setProcessingCallback(false);
        } else {
          // Keep processingCallback true so the interstitial shows the error
          setError(msg);
        }
        setLoading(false);
      });
  }, [setUser, returnTo]);

  // Poll approval status while pending — auto-redirect through GitHub OAuth when approved.
  useEffect(() => {
    if (!pendingApproval || !pendingUsername) return;
    const interval = setInterval(async () => {
      const approved = await checkApprovalStatus(pendingUsername);
      if (approved) {
        clearInterval(interval);
        // Re-initiate GitHub OAuth — user is approved now so the callback will succeed.
        try {
          const url = await getGitHubAuthURL();
          window.location.href = url;
        } catch {
          // Fallback: just tell them to try again
          setPendingApproval(false);
          setPendingUsername("");
          window.history.replaceState({}, "", "/admin/login");
        }
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [pendingApproval, pendingUsername]);

  async function handleLogin(e: FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      if (needsOTP) {
        const resp = await verifyOTP(otpCode);
        setUser(resp.user);
        navigateAfterLogin(returnTo);
        return;
      }
      const resp = await loginWithPassword(username, password);
      if (resp.otp_required) {
        setNeedsOTP(true);
      } else {
        setUser(resp.user);
        navigateAfterLogin(returnTo);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  async function handleGitHubLogin() {
    setError("");
    setLoading(true);
    try {
      // Persist returnTo so it survives the GitHub redirect round-trip.
      saveReturnTo(returnTo);
      const url = await getGitHubAuthURL();
      window.location.href = url;
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
      setLoading(false);
    }
  }

  // Show a redirect interstitial while processing the GitHub OAuth callback,
  // so users don't briefly see the sign-in screen again.
  if (processingCallback) {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          minHeight: "100vh",
          padding: "1rem",
          gap: "1rem",
        }}
      >
        {!error && <span className="spinner" style={{ width: 28, height: 28 }} />}
        {!error && (
          <p style={{ fontSize: "0.9375rem", color: "var(--color-text-secondary)" }}>
            Signing you in…
          </p>
        )}
        {error && (
          <div style={{ maxWidth: 400, textAlign: "center" }}>
            <div className="alert error" style={{ textAlign: "left", marginBottom: "1rem" }}>
              {error}
            </div>
            <button
              onClick={() => {
                setProcessingCallback(false);
                setError("");
                clearReturnTo();
                window.history.replaceState({}, "", "/admin/login");
              }}
              style={{
                background: "transparent",
                border: "1px solid var(--color-border)",
                borderRadius: "var(--radius-lg)",
                color: "var(--color-text-secondary)",
                fontSize: "0.8125rem",
                cursor: "pointer",
                padding: "0.5rem 1rem",
              }}
            >
              &larr; Back to sign in
            </button>
          </div>
        )}
      </div>
    );
  }

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        minHeight: "100vh",
        padding: "1rem",
      }}
    >
      <div style={{ width: 460, maxWidth: "100%" }}>
        {/* Logo */}
        <div style={{ textAlign: "center", marginBottom: "2rem" }}>
          <svg
            width="280"
            height="98"
            viewBox="32.92 0 1247.08 640"
            xmlns="http://www.w3.org/2000/svg"
            style={{ fillRule: "evenodd", clipRule: "evenodd", strokeLinejoin: "round", strokeMiterlimit: 2 }}
          >
            <path d="M.08 0v-.736h.068v.3C.203-.509.27-.545.347-.545c.029 0 .055.005.079.015.024.01.045.025.062.045.017.02.031.045.041.075.009.03.014.065.014.105V0H.475v-.289C.475-.352.464-.4.443-.433.422-.466.385-.483.334-.483c-.027 0-.052.006-.075.017C.236-.455.216-.439.2-.419c-.017.02-.029.044-.038.072-.009.028-.014.059-.014.093V0H.08Z" style={{ fill: "#f8b5cb", fillRule: "nonzero" }} transform="translate(32.92220721 521.8022953) scale(235.3092)" />
            <path d="M.051-.264c0-.036.007-.071.02-.105.013-.034.031-.064.055-.09.023-.026.052-.047.086-.063.033-.015.071-.023.112-.023.039 0 .076.007.109.021.033.014.062.033.087.058.025.025.044.054.058.088.014.035.021.072.021.113v.005H.121c.001.031.007.059.018.084.01.025.024.047.042.065.018.019.04.033.065.043.025.01.052.015.082.015.026 0 .049-.003.069-.01.02-.007.038-.016.054-.028C.466-.102.48-.115.492-.13c.011-.015.022-.03.032-.046l.057.03C.556-.097.522-.058.48-.03.437-.001.387.013.328.013.284.013.245.006.21-.01.175-.024.146-.045.123-.07.1-.095.082-.125.07-.159.057-.192.051-.227.051-.264ZM.128-.32h.396C.51-.375.485-.416.449-.441.412-.466.371-.479.325-.479c-.048 0-.089.013-.123.039-.034.026-.059.066-.074.12Z" style={{ fill: "var(--color-text-secondary, #8d8d8d)", fillRule: "nonzero" }} transform="translate(177.16674681 521.8022953) scale(235.3092)" />
            <path d="M.051-.267c0-.038.007-.074.021-.108.014-.033.033-.063.058-.088.025-.025.054-.045.087-.06.033-.015.069-.022.108-.022.043 0 .083.009.119.027.035.019.066.047.093.084v-.097h.067V0H.537v-.091C.508-.056.475-.029.44-.013.404.005.365.013.323.013.284.013.248.006.215-.01.182-.024.153-.045.129-.071.104-.096.085-.126.072-.16.058-.193.051-.229.051-.267Zm.279.218c.027 0 .054-.005.079-.015.025-.01.048-.024.068-.043.019-.018.035-.04.047-.067.012-.027.018-.056.018-.089 0-.031-.005-.059-.016-.086C.515-.375.501-.398.482-.417.462-.436.44-.452.415-.463.389-.474.361-.479.331-.479c-.031 0-.059.006-.084.017C.221-.45.199-.434.18-.415c-.019.02-.033.043-.043.068-.011.026-.016.053-.016.082 0 .029.005.056.016.082.011.026.025.049.044.069.019.02.041.036.066.047.025.012.053.018.083.018Z" style={{ fill: "var(--color-text-secondary, #8d8d8d)", fillRule: "nonzero" }} transform="translate(327.76463481 521.8022953) scale(235.3092)" />
            <path d="M.051-.267c0-.038.007-.074.021-.108.014-.033.033-.063.058-.088.025-.025.054-.045.087-.06.033-.015.069-.022.108-.022.043 0 .083.009.119.027.035.019.066.047.093.084v-.302h.068V0H.537v-.091C.508-.056.475-.029.44-.013.404.005.365.013.323.013.284.013.248.006.215-.01.182-.024.153-.045.129-.071.104-.096.085-.126.072-.16.058-.193.051-.229.051-.267Zm.279.218c.027 0 .054-.005.079-.015.025-.01.048-.024.068-.043.019-.018.035-.04.047-.067.011-.027.017-.056.017-.089 0-.031-.005-.059-.016-.086C.514-.375.5-.398.481-.417.462-.436.439-.452.414-.463.389-.474.361-.479.331-.479c-.031 0-.059.006-.084.017C.221-.45.199-.434.18-.415c-.019.02-.033.043-.043.068-.011.026-.016.053-.016.082 0 .029.005.056.016.082.011.026.025.049.044.069.019.02.041.036.066.047.025.012.053.018.083.018Z" style={{ fill: "var(--color-text-secondary, #8d8d8d)", fillRule: "nonzero" }} transform="translate(488.71612761 521.8022953) scale(235.3092)" />
            <path d="m.034-.062.043-.049c.017.019.035.034.054.044.018.01.037.015.057.015.013 0 .026-.002.038-.007.011-.004.021-.01.031-.018.009-.008.016-.017.021-.028.005-.011.008-.022.008-.035 0-.019-.005-.034-.014-.047C.263-.199.248-.21.229-.221.205-.234.183-.247.162-.259.14-.271.122-.284.107-.298.092-.311.08-.327.071-.344.062-.361.058-.381.058-.404c0-.021.004-.04.012-.058.007-.016.018-.031.031-.044.013-.013.028-.022.046-.029.018-.007.037-.01.057-.01.029 0 .056.006.079.019s.045.031.068.053l-.044.045C.291-.443.275-.456.258-.465.241-.474.221-.479.2-.479c-.022 0-.041.007-.056.02C.128-.445.12-.428.12-.408c0 .019.006.035.017.048.011.013.027.026.048.037.027.015.05.028.071.04.021.013.038.026.052.039.014.013.025.028.032.044.007.016.011.035.011.057 0 .021-.004.041-.011.059-.008.019-.019.036-.033.05-.014.015-.031.026-.05.035C.237.01.215.014.191.014c-.03 0-.059-.006-.086-.02C.077-.019.053-.037.034-.062Z" style={{ fill: "var(--color-text-secondary, #8d8d8d)", fillRule: "nonzero" }} transform="translate(649.90292961 521.8022953) scale(235.3092)" />
            <path d="M.051-.266c0-.04.007-.077.022-.111.014-.034.034-.063.059-.089.025-.025.054-.044.089-.058.035-.014.072-.021.113-.021.051 0 .098.01.139.03.041.021.075.049.1.085l-.05.043C.498-.418.47-.441.439-.456.408-.471.372-.479.331-.479c-.03 0-.058.005-.083.016C.222-.452.2-.436.181-.418.162-.399.148-.376.137-.35c-.011.026-.016.054-.016.084 0 .031.005.06.016.086.011.027.025.049.044.068.019.019.041.034.067.044.025.011.053.016.084.016.077 0 .141-.03.191-.09l.051.04c-.028.036-.062.064-.103.085C.43.004.384.014.332.014.291.014.254.007.219-.008.184-.022.155-.042.13-.067.105-.092.086-.121.072-.156.058-.19.051-.227.051-.266Z" style={{ fill: "var(--color-text-secondary, #8d8d8d)", fillRule: "nonzero" }} transform="translate(741.20289921 521.8022953) scale(235.3092)" />
            <path d="M.051-.267c0-.038.007-.074.021-.108.014-.033.033-.063.058-.088.025-.025.054-.045.087-.06.033-.015.069-.022.108-.022.043 0 .083.009.119.027.035.019.066.047.093.084v-.097h.067V0H.537v-.091C.508-.056.475-.029.44-.013.404.005.365.013.323.013.284.013.248.006.215-.01.182-.024.153-.045.129-.071.104-.096.085-.126.072-.16.058-.193.051-.229.051-.267Zm.279.218c.027 0 .054-.005.079-.015.025-.01.048-.024.068-.043.019-.018.035-.04.047-.067.012-.027.018-.056.018-.089 0-.031-.005-.059-.016-.086C.515-.375.501-.398.482-.417.462-.436.44-.452.415-.463.389-.474.361-.479.331-.479c-.031 0-.059.006-.084.017C.221-.45.199-.434.18-.415c-.019.02-.033.043-.043.068-.011.026-.016.053-.016.082 0 .029.005.056.016.082.011.026.025.049.044.069.019.02.041.036.066.047.025.012.053.018.083.018Z" style={{ fill: "var(--color-text-secondary, #8d8d8d)", fillRule: "nonzero" }} transform="translate(884.27089281 521.8022953) scale(235.3092)" />
            <path d="M.066-.736h.068V0H.066z" style={{ fill: "var(--color-text-secondary, #8d8d8d)", fillRule: "nonzero" }} transform="translate(1045.22238561 521.8022953) scale(235.3092)" />
            <path d="M.051-.264c0-.036.007-.071.02-.105.013-.034.031-.064.055-.09.023-.026.052-.047.086-.063.033-.015.071-.023.112-.023.039 0 .076.007.109.021.033.014.062.033.087.058.025.025.044.054.058.088.014.035.021.072.021.113v.005H.121c.001.031.007.059.018.084.01.025.024.047.042.065.018.019.04.033.065.043.025.01.052.015.082.015.026 0 .049-.003.069-.01.02-.007.038-.016.054-.028C.466-.102.48-.115.492-.13c.011-.015.022-.03.032-.046l.057.03C.556-.097.522-.058.48-.03.437-.001.387.013.328.013.284.013.245.006.21-.01.175-.024.146-.045.123-.07.1-.095.082-.125.07-.159.057-.192.051-.227.051-.264ZM.128-.32h.396C.51-.375.485-.416.449-.441.412-.466.371-.479.325-.479c-.048 0-.089.013-.123.039-.034.026-.059.066-.074.12Z" style={{ fill: "var(--color-text-secondary, #8d8d8d)", fillRule: "nonzero" }} transform="translate(1092.28422561 521.8022953) scale(235.3092)" />
            <circle cx="141.023" cy="338.36" r="117.472" style={{ fill: "#f8b5cb" }} transform="matrix(.581302 0 0 .58613 40.06479894 12.59842153)" />
            <circle cx="352.014" cy="268.302" r="33.095" style={{ fill: "#a2a2a2" }} transform="matrix(.59308 0 0 .58289 32.39345942 21.2386)" />
            <circle cx="352.014" cy="268.302" r="33.095" style={{ fill: "#a2a2a2" }} transform="matrix(.59308 0 0 .58289 32.39345942 88.80371146)" />
            <circle cx="352.014" cy="268.302" r="33.095" style={{ fill: "#a2a2a2" }} transform="matrix(.59308 0 0 .58289 120.7528627 88.80371146)" />
            <circle cx="352.014" cy="268.302" r="33.095" style={{ fill: "#a2a2a2" }} transform="matrix(.59308 0 0 .58289 120.99825939 21.2386)" />
            <circle cx="805.557" cy="336.915" r="118.199" style={{ fill: "#8d8d8d" }} transform="matrix(.5782 0 0 .58289 36.19871106 15.26642564)" />
            <circle cx="805.557" cy="336.915" r="118.199" style={{ fill: "#8d8d8d" }} transform="matrix(.5782 0 0 .58289 183.24041937 15.26642564)" />
            <path d="M680.282 124.808h-68.093v390.325h68.081v-28.23H640V153.228h40.282v-28.42Z" style={{ fill: "var(--color-text-secondary, #888)" }} transform="translate(34.2345 21.2386) scale(.58289)" />
            <path d="M680.282 124.808h-68.093v390.325h68.081v-28.23H640V153.228h40.282v-28.42Z" style={{ fill: "var(--color-text-secondary, #888)" }} transform="matrix(-.58289 0 0 .58289 1116.7719791 21.2386)" />
          </svg>
        </div>

        {/* Registration context banner */}
        {isRegistration && (
          <div
            style={{
              background: "var(--color-surface)",
              border: "1px solid var(--color-border)",
              borderRadius: "var(--radius-lg)",
              padding: "0.875rem 1rem",
              marginBottom: "1.5rem",
              textAlign: "center",
            }}
          >
            <div className="flex items-center gap-2" style={{ justifyContent: "center", marginBottom: "0.375rem" }}>
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="var(--color-primary)"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
                <line x1="8" y1="21" x2="16" y2="21" />
                <line x1="12" y1="17" x2="12" y2="21" />
              </svg>
              <span style={{ fontWeight: 500, fontSize: "0.875rem" }}>A device wants to join your network</span>
            </div>
            <p className="text-xs text-tertiary">Sign in to approve this registration request</p>
          </div>
        )}

        {error && (
          <div className="alert error" style={{ marginBottom: "1rem" }}>
            {error}
          </div>
        )}

        {/* Pending approval state */}
        {pendingApproval && (
          <div
            style={{
              background: "var(--color-surface)",
              border: "1px solid var(--color-border)",
              borderRadius: "var(--radius-lg)",
              padding: "1.5rem",
              textAlign: "center",
            }}
          >
            <svg
              width="40"
              height="40"
              viewBox="0 0 24 24"
              fill="none"
              stroke="var(--color-warning, #f59e0b)"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
              style={{ marginBottom: "0.75rem" }}
            >
              <circle cx="12" cy="12" r="10" />
              <polyline points="12 6 12 12 16 14" />
            </svg>
            <h3 style={{ fontSize: "1rem", marginBottom: "0.375rem" }}>Account Pending Approval</h3>
            <p className="text-sm text-secondary" style={{ marginBottom: "1rem" }}>
              Your account has been created{pendingUsername ? ` as "${pendingUsername}"` : ""}, but an administrator needs to approve it before you can sign in.
            </p>

            <div
              style={{
                background: "var(--color-bg, #111)",
                border: "1px solid var(--color-border)",
                borderRadius: "var(--radius)",
                padding: "0.75rem 1rem",
                textAlign: "left",
                marginBottom: "1rem",
              }}
            >
              <p className="text-xs text-tertiary" style={{ marginBottom: "0.375rem" }}>
                An admin can approve your account by running:
              </p>
              <div className="flex items-center gap-2">
                <code
                  style={{
                    flex: 1,
                    fontFamily: "var(--font-mono)",
                    fontSize: "0.8125rem",
                    color: "var(--color-text)",
                    wordBreak: "break-all",
                    userSelect: "all",
                  }}
                >
                  headscale users approve --name {pendingUsername || "<username>"}
                </code>
                <button
                  onClick={() => {
                    const cmd = `headscale users approve --name ${pendingUsername || "<username>"}`;
                    navigator.clipboard.writeText(cmd).then(() => {
                      setCopied(true);
                      setTimeout(() => setCopied(false), 2000);
                    });
                  }}
                  title="Copy to clipboard"
                  style={{
                    flexShrink: 0,
                    background: "transparent",
                    border: "1px solid var(--color-border)",
                    borderRadius: "var(--radius)",
                    padding: "0.25rem 0.375rem",
                    cursor: "pointer",
                    color: copied ? "var(--color-success, #22c55e)" : "var(--color-text-tertiary)",
                    transition: "color 0.15s",
                  }}
                >
                  {copied ? (
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                  ) : (
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                    </svg>
                  )}
                </button>
              </div>
            </div>

            <p className="text-xs text-tertiary" style={{ marginBottom: "0.75rem" }}>
              Waiting for approval<span className="dot-pulse">...</span>
            </p>
            <button
              onClick={() => {
                setPendingApproval(false);
                setPendingUsername("");
                window.history.replaceState({}, "", "/admin/login");
              }}
              className="outline"
              style={{ fontSize: "0.8125rem" }}
            >
              &larr; Back to sign in
            </button>
          </div>
        )}

        {/* Provider buttons (Tailscale-style) */}
        {!pendingApproval && !methods && (
          <div style={{ display: "flex", justifyContent: "center", padding: "1rem" }}>
            <span className="spinner" />
          </div>
        )}
        {!pendingApproval && methods && !showLocalLogin && (
          <div style={{ display: "flex", flexDirection: "column", gap: "0.625rem" }}>
            {methods?.github_auth_enabled && (
              <button
                onClick={handleGitHubLogin}
                disabled={loading}
                style={{
                  width: "100%",
                  padding: "0.625rem 1rem",
                  background: "var(--color-surface)",
                  border: "1px solid var(--color-border)",
                  borderRadius: "var(--radius-lg)",
                  color: "var(--color-text)",
                  fontSize: "0.9375rem",
                  fontWeight: 500,
                  cursor: "pointer",
                  transition: "all var(--transition)",
                }}
                onMouseOver={(e) => {
                  e.currentTarget.style.borderColor = "var(--color-border-hover)";
                  e.currentTarget.style.background = "var(--color-surface-2)";
                }}
                onMouseOut={(e) => {
                  e.currentTarget.style.borderColor = "var(--color-border)";
                  e.currentTarget.style.background = "var(--color-surface)";
                }}
              >
                <svg
                  width="18"
                  height="18"
                  viewBox="0 0 16 16"
                  fill="currentColor"
                  style={{ marginRight: "0.5rem", verticalAlign: "middle", position: "relative", top: "-1px" }}
                >
                  <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
                </svg>
                Sign in with GitHub
              </button>
            )}

            {methods?.local_auth_enabled && (
              <>
                {methods?.github_auth_enabled && (
                  <div
                    className="flex items-center gap-3"
                    style={{
                      margin: "0.25rem 0",
                      color: "var(--color-text-tertiary)",
                      fontSize: "0.75rem",
                    }}
                  >
                    <hr style={{ flex: 1, border: "none", borderTop: "1px solid var(--color-border)" }} />
                    or
                    <hr style={{ flex: 1, border: "none", borderTop: "1px solid var(--color-border)" }} />
                  </div>
                )}
                <button
                  onClick={() => setShowLocalLogin(true)}
                  style={{
                    width: "100%",
                    padding: "0.625rem 1rem",
                    background: "transparent",
                    border: "1px solid var(--color-border)",
                    borderRadius: "var(--radius-lg)",
                    color: "var(--color-text-secondary)",
                    fontSize: "0.875rem",
                    cursor: "pointer",
                    transition: "all var(--transition)",
                  }}
                  onMouseOver={(e) => {
                    e.currentTarget.style.borderColor = "var(--color-border-hover)";
                    e.currentTarget.style.color = "var(--color-text)";
                  }}
                  onMouseOut={(e) => {
                    e.currentTarget.style.borderColor = "var(--color-border)";
                    e.currentTarget.style.color = "var(--color-text-secondary)";
                  }}
                >
                  Sign in with password
                </button>
              </>
            )}
          </div>
        )}

        {/* Local login form */}
        {!pendingApproval && showLocalLogin && (
          <form onSubmit={handleLogin}>
            {!needsOTP ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                <div>
                  <label htmlFor="username" className="text-xs text-secondary" style={{ display: "block", marginBottom: 4 }}>Username</label>
                  <input
                    id="username"
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="Enter your username"
                    autoComplete="username"
                    autoFocus
                    required
                  />
                </div>
                <div>
                  <label htmlFor="password" className="text-xs text-secondary" style={{ display: "block", marginBottom: 4 }}>Password</label>
                  <input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter your password"
                    autoComplete="current-password"
                    required
                  />
                </div>
              </div>
            ) : (
              <div>
                <label htmlFor="otp" className="text-xs text-secondary" style={{ display: "block", marginBottom: 4 }}>One-time code</label>
                <input
                  id="otp"
                  type="text"
                  value={otpCode}
                  onChange={(e) => setOtpCode(e.target.value)}
                  placeholder="000000"
                  autoComplete="one-time-code"
                  autoFocus
                  maxLength={8}
                  style={{
                    textAlign: "center",
                    letterSpacing: "0.3em",
                    fontFamily: "var(--font-mono)",
                  }}
                  required
                />
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              style={{
                width: "100%",
                marginTop: "1rem",
                padding: "0.625rem",
                background: "var(--color-primary)",
                color: "#fff",
                border: "none",
                borderRadius: "var(--radius-lg)",
                fontSize: "0.9375rem",
                fontWeight: 500,
                cursor: loading ? "not-allowed" : "pointer",
              }}
            >
              {loading ? <span className="spinner" style={{ width: 18, height: 18 }} /> : needsOTP ? "Verify" : "Sign In"}
            </button>

            {methods?.github_auth_enabled && (
              <button
                type="button"
                onClick={() => { setShowLocalLogin(false); setError(""); }}
                style={{
                  width: "100%",
                  marginTop: "0.5rem",
                  padding: "0.5rem",
                  background: "transparent",
                  border: "none",
                  color: "var(--color-text-tertiary)",
                  fontSize: "0.8125rem",
                  cursor: "pointer",
                }}
              >
                &larr; Other sign-in options
              </button>
            )}
          </form>
        )}

        {/* Footer text */}
        <p className="text-xs text-tertiary" style={{ textAlign: "center", marginTop: "2rem" }}>
          Self-hosted Tailscale control server
        </p>
      </div>
    </div>
  );
}
