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
    console.log("[LOGIN_ATTEMPT] Attempting login with email:", email ? "[provided]" : "[empty]");
    try {
      const response = await api.post("/login", {
        username: email,
        password: password,
      });

      console.log("[LOGIN_SUCCESS] Server responded:", response.status, "has token:", !!response.data?.access_token);

      if (response.data?.access_token) {
        localStorage.setItem("token", response.data.access_token);
        console.log("[TOKEN_STORED] Token written to localStorage successfully");

        // Brief delay to guarantee localStorage write is flushed before navigation
        setTimeout(() => {
          navigate("/");
        }, 50);
      } else {
        setError(response.data?.error || "Invalid credentials.");
      }
    } catch (err) {
      console.error("Login error:", err);
      const errorData = err.response?.data;
      if (errorData?.email_unverified) {
        // Email not verified - redirect to verification
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
    <div className="flex items-center justify-center h-screen bg-slate-950">
      <div className="w-full max-w-md px-4">
        <div className="bg-slate-800/40 border border-slate-700/60 rounded-2xl p-8 shadow-2xl shadow-black/40">
          <div className="flex flex-col items-center mb-8">
            <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center mb-4">
              <Shield size={28} className="text-cyan-400" />
            </div>
            <h1 className="text-2xl font-bold text-white tracking-wide">
              SOCRA AI
            </h1>
            <p className="text-xs text-slate-500 mt-1.5 font-medium tracking-wider uppercase">
              Security Investigation Platform
            </p>
          </div>

          <div className="space-y-4">
            <div>
              <label className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1.5 block">
                Email
              </label>
              <input
                type="email"
                placeholder="Enter your email"
                className="w-full bg-slate-900/50 border border-slate-800 rounded-lg px-4 py-2.5 text-sm text-slate-200 placeholder:text-slate-600 outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/30 transition-all"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && login()}
              />
            </div>

            <div>
              <label className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1.5 block">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  placeholder="Enter your password"
                  className="w-full bg-slate-900/50 border border-slate-800 rounded-lg px-4 py-2.5 pr-10 text-sm text-slate-200 placeholder:text-slate-600 outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/30 transition-all"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && login()}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <div className="flex justify-end">
              <Link
                to="/forgot-password"
                className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold"
              >
                Forgot Password?
              </Link>
            </div>

            <button
              onClick={login}
              disabled={loading}
              className="w-full bg-cyan-600 hover:bg-cyan-500 disabled:bg-cyan-600/50 text-white text-sm font-bold py-2.5 rounded-lg transition-all duration-150 flex items-center justify-center gap-2 mt-2"
            >
              {loading ? (
                <>
                  <Loader2 size={16} className="animate-spin" />
                  Authenticating...
                </>
              ) : (
                "Sign In"
              )}
            </button>
          </div>

          {error && (
            <div className="mt-4 rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-2.5 text-xs text-red-300 text-center">
              {error}
            </div>
          )}

          <div className="mt-6 text-center">
            <p className="text-xs text-slate-500">
              Don't have an account?{" "}
              <Link
                to="/register"
                className="text-cyan-400 hover:text-cyan-300 font-semibold"
              >
                Create Account
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Login;