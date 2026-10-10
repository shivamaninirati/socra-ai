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
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#080f1e] px-4 py-8 text-slate-100">
      {/* Subtle background decoration */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute left-1/2 top-0 h-72 w-96 -translate-x-1/2 rounded-full bg-slate-700/10 blur-3xl" />
        <div className="absolute bottom-0 right-0 h-64 w-64 rounded-full bg-blue-950/10 blur-3xl" />
      </div>

      <div className="relative w-full max-w-md">
        <div className="rounded-2xl border border-slate-800/80 bg-slate-950/80 p-7 shadow-2xl shadow-black/30 backdrop-blur-xl sm:p-8">
          {/* Branding */}
          <div className="mb-8 flex flex-col items-center">
            <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl border border-slate-700/70 bg-slate-900 shadow-lg shadow-black/20">
              <Shield size={28} className="text-slate-200" />
            </div>

            <h1 className="text-2xl font-bold tracking-wide text-slate-100">
              SOCRA AI
            </h1>

            <p className="mt-2 text-center text-[11px] font-medium uppercase tracking-[0.18em] text-slate-500">
              Security Investigation Platform
            </p>

            <div className="mt-5 h-px w-16 bg-slate-700/80" />
          </div>

          <div className="mb-6">
            <h2 className="text-lg font-semibold text-slate-100">
              Welcome back
            </h2>
            <p className="mt-1 text-sm text-slate-400">
              Sign in to access your security operations console.
            </p>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              login();
            }}
            className="space-y-5"
          >
            {/* Email */}
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
                className="w-full rounded-lg border border-slate-800 bg-slate-900/70 px-4 py-3 text-sm text-slate-200 outline-none transition placeholder:text-slate-600 hover:border-slate-700 focus:border-slate-600 focus:ring-2 focus:ring-slate-500/20"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>

            {/* Password */}
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
                  className="text-xs font-medium text-slate-400 transition hover:text-slate-200"
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
                  className="w-full rounded-lg border border-slate-800 bg-slate-900/70 px-4 py-3 pr-11 text-sm text-slate-200 outline-none transition placeholder:text-slate-600 hover:border-slate-700 focus:border-slate-600 focus:ring-2 focus:ring-slate-500/20"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />

                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  className="absolute right-3 top-1/2 -translate-y-1/2 rounded p-1 text-slate-500 transition hover:text-slate-200 focus:outline-none focus:ring-2 focus:ring-slate-500/40"
                >
                  {showPassword ? (
                    <EyeOff size={17} />
                  ) : (
                    <Eye size={17} />
                  )}
                </button>
              </div>
            </div>

            {/* Error message */}
            {error && (
              <div
                role="alert"
                className="rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-300"
              >
                {error}
              </div>
            )}

            {/* Sign in */}
            <button
              type="submit"
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-lg border border-slate-600/70 bg-slate-800 py-3 text-sm font-semibold text-slate-100 transition duration-200 hover:border-slate-500 hover:bg-slate-700 focus:outline-none focus:ring-2 focus:ring-slate-500/40 disabled:cursor-not-allowed disabled:opacity-50"
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

          {/* Registration */}
          <div className="mt-7 border-t border-slate-800/80 pt-5 text-center">
            <p className="text-sm text-slate-500">
              Don't have an account?{" "}
              <Link
                to="/register"
                className="font-semibold text-slate-300 transition hover:text-white"
              >
                Create account
              </Link>
            </p>
          </div>
        </div>

        <p className="mt-5 text-center text-[10px] font-medium uppercase tracking-[0.16em] text-slate-600">
          SOCRA AI · Security Operations
        </p>
      </div>
    </div>
  );
}

export default Login;