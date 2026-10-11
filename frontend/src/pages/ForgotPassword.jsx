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
    "w-full rounded-lg border border-[#263957] bg-[#101b30] px-4 py-2.5 text-sm text-slate-100 outline-none transition duration-200 placeholder:text-slate-500 hover:border-[#3b5278] focus:border-blue-400/80 focus:ring-2 focus:ring-blue-500/20";

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#070d1b] px-4 py-8 text-slate-100">
      {/* Subtle background decoration - matching Login.jsx */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="absolute left-1/2 top-[-180px] h-[420px] w-[600px] -translate-x-1/2 rounded-full bg-blue-600/[0.09] blur-[110px]" />
        <div className="absolute bottom-[-150px] left-[-100px] h-[350px] w-[350px] rounded-full bg-indigo-600/[0.07] blur-[100px]" />
        <div className="absolute bottom-[-160px] right-[-100px] h-[400px] w-[400px] rounded-full bg-sky-500/[0.06] blur-[110px]" />
        <div className="absolute inset-0 bg-gradient-to-b from-[#0b1730]/30 via-transparent to-[#030712]/40" />
      </div>

      <div className="relative w-full max-w-sm">
        <div className="rounded-2xl border border-[#253552]/80 bg-[#050b1b]/95 p-5 shadow-[0_24px_80px_rgba(0,0,0,0.45)] backdrop-blur-xl sm:p-6">
          {/* Header */}
          <div className="mb-6 flex flex-col items-center text-center">
            <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-2xl border border-blue-400/20 bg-gradient-to-br from-[#172844] to-[#0d172b] shadow-lg shadow-blue-950/30">
              <Shield size={26} strokeWidth={1.8} className="text-blue-200" />
            </div>

            <h1 className="text-xl font-bold tracking-wide text-white">
              Forgot Password
            </h1>

            <p className="mt-1 text-sm leading-relaxed text-slate-400">
              Enter your registered email address and we’ll help you recover
              access to your account.
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email */}
            <div>
              <label
                htmlFor="reset-email"
                className="mb-2 block text-xs font-semibold uppercase tracking-wider text-blue-200/60"
              >
                Email Address
              </label>

              <div className="relative">
                <Mail
                  size={17}
                  className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400"
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
              className="flex w-full items-center justify-center gap-2 rounded-lg border border-[#233b60] bg-[#102344] py-3 text-sm font-semibold text-white shadow-lg shadow-black/20 transition duration-200 hover:border-[#31578b] hover:bg-[#17325b] focus:outline-none focus:ring-2 focus:ring-blue-500/30 disabled:cursor-not-allowed disabled:opacity-50"
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
          <div className="mt-7 border-t border-[#202d45] pt-5 text-center">
            <Link
              to="/login"
              className="inline-flex items-center gap-2 text-xs font-medium text-blue-300/80 transition hover:text-blue-200"
            >
              <ArrowLeft size={14} />
              Back to Sign In
            </Link>
          </div>
        </div>

        <p className="mt-5 text-center text-[10px] font-medium uppercase tracking-[0.18em] text-slate-500/80">
          SOCRA AI · Secure Account Recovery
        </p>
      </div>
    </div>
  );
}

export default ForgotPassword;