
import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Shield, Loader2, Eye, EyeOff } from "lucide-react";
import api from "../services/api";

function Login() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const login = async () => {
    if (!email.trim() || !password.trim()) {
      setError("Please enter both email and password.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const response = await api.post("/login", {
        username: email,
        password,
      });

      if (response.data?.access_token) {
        localStorage.setItem("token", response.data.access_token);
        navigate("/");
      } else {
        setError(response.data?.error || "Invalid credentials.");
      }
    } catch (err) {
      const errorData = err.response?.data;

      if (errorData?.email_unverified) {
        navigate("/verify-email", {
          state: { email: errorData.email || email.trim() },
        });
        return;
      }

      setError(errorData?.error || "Invalid email or password.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#070d1b] px-4 py-8 text-slate-100">
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="absolute left-1/2 top-[-180px] h-[420px] w-[600px] -translate-x-1/2 rounded-full bg-blue-600/[0.09] blur-[110px]" />
        <div className="absolute bottom-[-150px] left-[-100px] h-[350px] w-[350px] rounded-full bg-indigo-600/[0.07] blur-[100px]" />
        <div className="absolute bottom-[-160px] right-[-100px] h-[400px] w-[400px] rounded-full bg-sky-500/[0.06] blur-[110px]" />
        <div className="absolute inset-0 bg-gradient-to-b from-[#0b1730]/30 via-transparent to-[#030712]/40" />
      </div>

      <div className="relative w-full max-w-sm">
        <div className="rounded-2xl border border-[#253552]/80 bg-[#050b1b]/95 p-5 shadow-[0_24px_80px_rgba(0,0,0,0.45)] backdrop-blur-xl sm:p-6">
          <div className="mb-6 flex flex-col items-center">
            <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-2xl border border-blue-400/20 bg-gradient-to-br from-[#172844] to-[#0d172b] shadow-lg shadow-blue-950/30">
              <Shield
                size={26}
                strokeWidth={1.8}
                className="text-blue-200"
              />
            </div>

            <h1 className="text-xl font-bold tracking-wide text-white">
              SOCRA AI
            </h1>

            <p className="mt-1 text-center text-[10px] font-medium uppercase tracking-[0.2em] text-blue-200/55">
              Security Investigation Platform
            </p>

            <div className="mt-4 h-px w-16 bg-gradient-to-r from-transparent via-blue-400/50 to-transparent" />
          </div>

          <div className="mb-5">
            <h2 className="text-lg font-semibold text-slate-100">
              Welcome back
            </h2>
            <p className="mt-1 text-sm leading-6 text-slate-400">
              Sign in to access your security operations console.
            </p>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              login();
            }}
            className="space-y-4"
          >
            <div>
              <label
                htmlFor="login-email"
                className="mb-2 block text-xs font-semibold uppercase tracking-wider text-slate-400"
              >
                Email
              </label>

              <input
                id="login-email"
                type="email"
                autoComplete="email"
                placeholder="Enter your email"
                required
                className="w-full rounded-lg border border-[#263957] bg-[#101b30] px-4 py-2.5 text-sm text-slate-100 outline-none transition duration-200 placeholder:text-slate-500 hover:border-[#3b5278] focus:border-blue-400/80 focus:ring-2 focus:ring-blue-500/20"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>

            <div>
              <div className="mb-2 flex items-center justify-between">
                <label
                  htmlFor="login-password"
                  className="block text-xs font-semibold uppercase tracking-wider text-slate-400"
                >
                  Password
                </label>

                <Link
                  to="/forgot-password"
                  className="text-xs font-medium text-blue-300/80 transition hover:text-blue-200"
                >
                  Forgot password?
                </Link>
              </div>

              <div className="relative">
                <input
                id="login-password"
                type={showPassword ? "text" : "password"}
                autoComplete="current-password"
                placeholder="Enter your password"
                required
                className="w-full rounded-lg border border-[#263957] bg-[#101b30] px-4 py-2.5 text-sm text-slate-100 outline-none transition duration-200 placeholder:text-slate-500 hover:border-[#3b5278] focus:border-blue-400/80 focus:ring-2 focus:ring-blue-500/20"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />

                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  className="absolute right-3 top-1/2 -translate-y-1/2 rounded p-1 text-slate-400 transition hover:text-blue-200 focus:outline-none focus:ring-2 focus:ring-blue-500/30"
                >
                  {showPassword ? (
                    <EyeOff size={17} />
                  ) : (
                    <Eye size={17} />
                  )}
                </button>
              </div>
            </div>

            {error && (
              <div
                role="alert"
                className="rounded-lg border border-red-500/25 bg-red-500/10 px-4 py-3 text-sm text-red-300"
              >
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-lg border border-[#233b60] bg-[#102344] py-2.5 text-sm font-semibold text-white shadow-lg shadow-black/20 transition duration-200 hover:border-[#31578b] hover:bg-[#17325b] focus:outline-none focus:ring-2 focus:ring-blue-500/30 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? (
                <>
                  <Loader2 size={17} className="animate-spin" />
                  Authenticating...
                </>
              ) : (
                "Sign In"
              )}
            </button>
          </form>

          <div className="mt-5 border-t border-[#202d45] pt-4 text-center">
            <p className="text-sm text-slate-400">
              Don't have an account?{" "}
              <Link
                to="/register"
                className="font-semibold text-blue-200 transition hover:text-white"
              >
                Create account
              </Link>
            </p>
          </div>
        </div>

        <p className="mt-5 text-center text-[10px] font-medium uppercase tracking-[0.18em] text-slate-500/80">
          SOCRA AI · Security Operations
        </p>
      </div>
    </div>
  );
}

export default Login;