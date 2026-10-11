import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Shield, Loader2, Eye, EyeOff } from "lucide-react";
import api from "../services/api";

function Register() {
  const navigate = useNavigate();
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const register = async () => {
    setError("");

    if (!fullName.trim()) {
      setError("Full name is required.");
      return;
    }
    if (!email.trim()) {
      setError("Email is required.");
      return;
    }
    if (!password) {
      setError("Password is required.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }

    setLoading(true);
    try {
      const response = await api.post("/register", {
        full_name: fullName.trim(),
        email: email.trim().toLowerCase(),
        password,
        confirm_password: confirmPassword,
      });

      if (response.data?.success) {
        navigate("/verify-email", {
          state: { email: email.trim().toLowerCase() },
        });
      } else {
        setError(response.data?.error || "Registration failed.");
      }
    } catch (err) {
      setError(
        err.response?.data?.error || "Registration failed. Please try again."
      );
    } finally {
      setLoading(false);
    }
  };

  const inputClass =
    "w-full rounded-lg border border-[#263957] bg-[#101b30] px-4 py-2.5 text-sm text-slate-100 outline-none transition duration-200 placeholder:text-slate-500 hover:border-[#3b5278] focus:border-blue-400/80 focus:ring-2 focus:ring-blue-500/20";

  const labelClass =
    "mb-2 block text-xs font-semibold uppercase tracking-wider text-blue-200/60";

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#070d1b] px-4 py-6 text-slate-100">
      {/* Subtle background decoration - matching Login.jsx */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="absolute left-1/2 top-[-180px] h-[420px] w-[600px] -translate-x-1/2 rounded-full bg-blue-600/[0.09] blur-[110px]" />
        <div className="absolute bottom-[-150px] left-[-100px] h-[350px] w-[350px] rounded-full bg-indigo-600/[0.07] blur-[100px]" />
        <div className="absolute bottom-[-160px] right-[-100px] h-[400px] w-[400px] rounded-full bg-sky-500/[0.06] blur-[110px]" />
        <div className="absolute inset-0 bg-gradient-to-b from-[#0b1730]/30 via-transparent to-[#030712]/40" />
      </div>

      <div className="relative w-full max-w-sm">
        <div className="rounded-2xl border border-[#253552]/80 bg-[#050b1b]/95 p-5 shadow-[0_24px_80px_rgba(0,0,0,0.45)] backdrop-blur-xl sm:p-6">
          {/* Branding */}
          <div className="mb-5 flex flex-col items-center">
            <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-2xl border border-blue-400/20 bg-gradient-to-br from-[#172844] to-[#0d172b] shadow-lg shadow-blue-950/30">
              <Shield
                size={26}
                strokeWidth={1.8}
                className="text-blue-200"
              />
            </div>

            <h1 className="text-2xl font-bold tracking-wide text-white">
              Create Account
            </h1>

            <p className="mt-2 text-center text-[11px] font-medium uppercase tracking-[0.2em] text-blue-200/55">
              SOCRA AI Security Investigation Platform
            </p>

            <div className="mt-4 h-px w-16 bg-gradient-to-r from-transparent via-blue-400/50 to-transparent" />
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              register();
            }}
            className="space-y-3"
          >
            {/* Full name */}
            <div>
              <label htmlFor="register-name" className={labelClass}>
                Full Name
              </label>
              <input
                id="register-name"
                type="text"
                autoComplete="name"
                placeholder="Enter your full name"
                className={inputClass}
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                required
              />
            </div>

            {/* Email */}
            <div>
              <label htmlFor="register-email" className={labelClass}>
                Email Address
              </label>
              <input
                id="register-email"
                type="email"
                autoComplete="email"
                placeholder="Enter your email"
                className={inputClass}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>

            {/* Password */}
            <div>
              <label htmlFor="register-password" className={labelClass}>
                Password
              </label>

              <div className="relative">
                <input
                  id="register-password"
                  type={showPassword ? "text" : "password"}
                  autoComplete="new-password"
                  placeholder="Create a strong password"
                  className={`${inputClass} pr-11`}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />

                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  className="absolute right-3 top-1/2 -translate-y-1/2 rounded p-1 text-slate-400 transition hover:text-blue-200 focus:outline-none focus:ring-2 focus:ring-blue-500/30"
                >
                  {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
                </button>
              </div>

              <p className="mt-2 text-[11px] leading-relaxed text-slate-500">
                Use at least 8 characters with uppercase and lowercase letters,
                a number, and a special character.
              </p>
            </div>

            {/* Confirm password */}
            <div>
              <label htmlFor="register-confirm-password" className={labelClass}>
                Confirm Password
              </label>

              <div className="relative">
                <input
                  id="register-confirm-password"
                  type={showConfirmPassword ? "text" : "password"}
                  autoComplete="new-password"
                  placeholder="Confirm your password"
                  className={`${inputClass} pr-11`}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                />

                <button
                  type="button"
                  onClick={() => setShowConfirmPassword((prev) => !prev)}
                  aria-label={showConfirmPassword ? "Hide confirm password" : "Show confirm password"}
                  className="absolute right-3 top-1/2 -translate-y-1/2 rounded p-1 text-slate-400 transition hover:text-blue-200 focus:outline-none focus:ring-2 focus:ring-blue-500/30"
                >
                  {showConfirmPassword ? (
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

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-lg border border-[#233b60] bg-[#102344] py-2.5 text-sm font-semibold text-white shadow-lg shadow-black/20 transition duration-200 hover:border-[#31578b] hover:bg-[#17325b] focus:outline-none focus:ring-2 focus:ring-blue-500/30 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? (
                <>
                  <Loader2 size={17} className="animate-spin" />
                  Creating Account...
                </>
              ) : (
                "Create Account"
              )}
            </button>
          </form>

          {/* Sign in */}
          <div className="mt-5 border-t border-[#202d45] pt-4 text-center">
            <p className="text-sm text-slate-400">
              Already have an account?{" "}
              <Link
                to="/login"
                className="font-semibold text-blue-200 transition hover:text-white"
              >
                Sign in
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

export default Register;