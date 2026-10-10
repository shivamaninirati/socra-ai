import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Shield, Loader2, ArrowLeft, Mail } from "lucide-react";
import api from "../services/api";

function ForgotPassword() {
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event) => {
    event?.preventDefault();

    setError("");
    setSuccess("");

    const normalizedEmail = email.trim().toLowerCase();

    if (!normalizedEmail) {
      setError("Email is required.");
      return;
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      setError("Please enter a valid email address.");
      return;
    }

    setLoading(true);

    try {
      const response = await api.post("/forgot-password", {
        email: normalizedEmail,
      });

      if (response.data?.success) {
        setSuccess(
          response.data?.message ||
            "If the account is eligible, a password reset code will be sent."
        );

        setTimeout(() => {
          navigate("/reset-password", {
            state: { email: normalizedEmail },
          });
        }, 1500);
      } else {
        setError(
          response.data?.error || "Failed to send reset code. Please try again."
        );
      }
    } catch (err) {
      setError(
        err.response?.data?.error ||
          "Failed to send reset code. Please try again."
      );
    } finally {
      setLoading(false);
    }
  };

  const inputClass =
    "w-full rounded-xl border border-slate-700/70 bg-slate-950/70 px-4 py-3 text-sm text-slate-200 placeholder:text-slate-600 outline-none transition-colors focus:border-slate-500 focus:ring-1 focus:ring-slate-500/20";

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4 py-10 text-slate-200">
      <div className="w-full max-w-md">
        <div className="rounded-2xl border border-slate-800/90 bg-slate-900/70 p-6 shadow-2xl shadow-black/30 sm:p-8">
          {/* Header */}
          <div className="mb-8 flex flex-col items-center text-center">
            <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl border border-slate-700/70 bg-slate-800/70">
              <Shield size={27} className="text-slate-300" />
            </div>

            <h1 className="text-2xl font-bold tracking-tight text-slate-100">
              Forgot Password
            </h1>

            <p className="mt-2 text-sm leading-relaxed text-slate-400">
              Enter your registered email address and we’ll help you recover
              access to your account.
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Email */}
            <div>
              <label
                htmlFor="reset-email"
                className="mb-2 block text-xs font-semibold uppercase tracking-wider text-slate-400"
              >
                Email Address
              </label>

              <div className="relative">
                <Mail
                  size={17}
                  className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500"
                />

                <input
                  id="reset-email"
                  type="email"
                  name="email"
                  autoComplete="email"
                  placeholder="you@example.com"
                  className={`${inputClass} pl-10`}
                  value={email}
                  onChange={(event) => {
                    setEmail(event.target.value);
                    setError("");
                  }}
                  required
                  disabled={loading}
                />
              </div>

              <p className="mt-2 text-xs leading-relaxed text-slate-500">
                If your account is eligible, you’ll receive a verification code
                by email.
              </p>
            </div>

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-xl border border-slate-600/60 bg-slate-700 px-4 py-3 text-sm font-semibold text-white transition-colors hover:bg-slate-600 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? (
                <>
                  <Loader2 size={16} className="animate-spin" />
                  Sending Reset Code...
                </>
              ) : (
                "Send Reset Code"
              )}
            </button>
          </form>

          {/* Error */}
          {error && (
            <div
              role="alert"
              className="mt-5 rounded-xl border border-red-900/60 bg-red-950/30 px-4 py-3 text-sm text-red-300"
            >
              {error}
            </div>
          )}

          {/* Success */}
          {success && (
            <div
              role="status"
              className="mt-5 rounded-xl border border-emerald-900/60 bg-emerald-950/30 px-4 py-3 text-sm text-emerald-300"
            >
              {success}
            </div>
          )}

          {/* Back to Login */}
          <div className="mt-7 border-t border-slate-800 pt-5 text-center">
            <Link
              to="/login"
              className="inline-flex items-center gap-2 text-xs font-medium text-slate-500 transition-colors hover:text-slate-300"
            >
              <ArrowLeft size={14} />
              Back to Sign In
            </Link>
          </div>
        </div>

        <p className="mt-5 text-center text-xs text-slate-600">
          SOCRA AI · Secure Account Recovery
        </p>
      </div>
    </div>
  );
}

export default ForgotPassword;