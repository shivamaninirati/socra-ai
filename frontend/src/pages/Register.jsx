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
    "w-full rounded-lg border border-slate-800 bg-slate-900/70 px-4 py-3 text-sm text-slate-200 outline-none transition placeholder:text-slate-600 hover:border-slate-700 focus:border-slate-600 focus:ring-2 focus:ring-slate-500/20";

  const labelClass =
    "mb-2 block text-xs font-semibold uppercase tracking-wider text-slate-400";

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
          <div className="mb-7 flex flex-col items-center">
            <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl border border-slate-700/70 bg-slate-900 shadow-lg shadow-black/20">
              <Shield size={28} className="text-slate-200" />
            </div>

            <h1 className="text-2xl font-bold tracking-wide text-slate-100">
              Create Account
            </h1>

            <p className="mt-2 text-center text-[11px] font-medium uppercase tracking-[0.18em] text-slate-500">
              SOCRA AI Security Platform
            </p>

            <div className="mt-5 h-px w-16 bg-slate-700/80" />
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              register();
            }}
            className="space-y-4"
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
                  className="absolute right-3 top-1/2 -translate-y-1/2 rounded p-1 text-slate-500 transition hover:text-slate-200 focus:outline-none focus:ring-2 focus:ring-slate-500/40"
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
                  onClick={() =>
                    setShowConfirmPassword((prev) => !prev)
                  }
                  aria-label={
                    showConfirmPassword
                      ? "Hide confirm password"
                      : "Show confirm password"
                  }
                  className="absolute right-3 top-1/2 -translate-y-1/2 rounded p-1 text-slate-500 transition hover:text-slate-200 focus:outline-none focus:ring-2 focus:ring-slate-500/40"
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
              className="mt-2 flex w-full items-center justify-center gap-2 rounded-lg border border-slate-600/70 bg-slate-800 py-3 text-sm font-semibold text-slate-100 transition duration-200 hover:border-slate-500 hover:bg-slate-700 focus:outline-none focus:ring-2 focus:ring-slate-500/40 disabled:cursor-not-allowed disabled:opacity-50"
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
          <div className="mt-7 border-t border-slate-800/80 pt-5 text-center">
            <p className="text-sm text-slate-500">
              Already have an account?{" "}
              <Link
                to="/login"
                className="font-semibold text-slate-300 transition hover:text-white"
              >
                Sign In
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

export default Register;