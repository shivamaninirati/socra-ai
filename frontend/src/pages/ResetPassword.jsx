import { useState, useEffect, useRef } from "react";
import { useNavigate, useLocation, Link } from "react-router-dom";
import { Shield, Loader2, ArrowLeft, Eye, EyeOff } from "lucide-react";
import api from "../services/api";

function ResetPassword() {
  const navigate = useNavigate();
  const location = useLocation();
  const email = location.state?.email || "";

  const [otp, setOtp] = useState(["", "", "", "", "", ""]);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);
  const [resendLoading, setResendLoading] = useState(false);
  const [countdown, setCountdown] = useState(60);
  const [canResend, setCanResend] = useState(false);
  const [otpVerified, setOtpVerified] = useState(false);
  const inputRefs = useRef([]);

  useEffect(() => {
    if (!email) {
      navigate("/forgot-password", { replace: true });
      return;
    }

    inputRefs.current[0]?.focus();
  }, [email, navigate]);

  useEffect(() => {
    if (countdown <= 0) {
      setCanResend(true);
      return;
    }

    const timer = setTimeout(() => {
      setCountdown((previous) => previous - 1);
    }, 1000);

    return () => clearTimeout(timer);
  }, [countdown]);

  const handleOtpChange = (index, value) => {
    if (!/^\d*$/.test(value)) return;

    const digit = value.slice(-1);
    const nextOtp = [...otp];
    nextOtp[index] = digit;

    setOtp(nextOtp);
    setOtpVerified(false);
    setError("");
    setSuccess("");

    if (digit && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handleKeyDown = (index, event) => {
    if (
      event.key === "Backspace" &&
      !otp[index] &&
      index > 0
    ) {
      inputRefs.current[index - 1]?.focus();
    }

    if (event.key === "ArrowLeft" && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }

    if (event.key === "ArrowRight" && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handlePaste = (event) => {
    event.preventDefault();

    const pasted = event.clipboardData
      .getData("text")
      .replace(/\D/g, "")
      .slice(0, 6);

    if (!pasted) return;

    const nextOtp = Array(6).fill("");

    pasted.split("").forEach((digit, index) => {
      nextOtp[index] = digit;
    });

    setOtp(nextOtp);
    setOtpVerified(false);
    setError("");
    setSuccess("");

    inputRefs.current[Math.min(pasted.length, 5)]?.focus();
  };

  const verifyOtp = () => {
    const otpCode = otp.join("");

    if (otpCode.length !== 6) {
      setError("Please enter the complete 6-digit code.");
      return false;
    }

    /*
     * This only checks that six digits have been entered.
     * Actual OTP verification must happen on the backend
     * when /reset-password is called.
     */
    setOtpVerified(true);
    setError("");

    return true;
  };

  const handleResetPassword = async (event) => {
    event?.preventDefault();

    setError("");
    setSuccess("");

    const otpCode = otp.join("");

    if (otpCode.length !== 6) {
      setError("Please enter the complete 6-digit code.");
      return;
    }

    if (!newPassword) {
      setError("New password is required.");
      return;
    }

    if (newPassword.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }

    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);

    try {
      const response = await api.post("/reset-password", {
        email,
        otp: otpCode,
        new_password: newPassword,
        confirm_password: confirmPassword,
      });

      if (response.data?.success) {
        setSuccess("Password reset successful! Redirecting to login...");
        setTimeout(() => navigate("/login", { replace: true }), 2000);
      } else {
        setError(response.data?.error || "Password reset failed.");
      }
    } catch (err) {
      setError(
        err.response?.data?.error ||
          "Password reset failed. Please try again."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    setResendLoading(true);
    setError("");
    setSuccess("");

    try {
      const response = await api.post("/forgot-password", { email });

      if (response.data?.success) {
        setSuccess("A new reset code has been sent.");
        setOtp(["", "", "", "", "", ""]);
        setOtpVerified(false);
        setCountdown(60);
        setCanResend(false);
        setNewPassword("");
        setConfirmPassword("");
        inputRefs.current[0]?.focus();
      } else {
        setError(response.data?.error || "Failed to resend code.");
      }
    } catch (err) {
      setError(
        err.response?.data?.error || "Failed to resend code."
      );
    } finally {
      setResendLoading(false);
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

            <h1 className="text-2xl font-bold tracking-wide text-white">
              Reset Password
            </h1>

            <p className="mt-2 text-sm text-slate-400">
              Enter your reset code and choose a new password.
            </p>

            <p className="mt-3 max-w-full break-all text-sm font-medium text-blue-200">
              {email}
            </p>
          </div>

          <form onSubmit={handleResetPassword} className="space-y-4">
            {/* OTP Input */}
            <div>
              <label
                htmlFor="otp-0"
                className="mb-2 block text-xs font-semibold uppercase tracking-wider text-slate-400"
              >
                Verification Code
              </label>

              <div className="flex justify-center gap-2">
                {otp.map((digit, index) => (
                  <input
                    key={index}
                    id={`otp-${index}`}
                    ref={(element) => {
                      inputRefs.current[index] = element;
                    }}
                    type="text"
                    inputMode="numeric"
                    autoComplete={index === 0 ? "one-time-code" : "off"}
                    pattern="[0-9]*"
                    maxLength={1}
                    aria-label={`Verification code digit ${index + 1}`}
                    value={digit}
                    onChange={(event) =>
                      handleOtpChange(index, event.target.value)
                    }
                    onKeyDown={(event) => handleKeyDown(index, event)}
                    onPaste={handlePaste}
                    className="w-12 h-14 text-center text-xl font-bold bg-[#101b30] border border-[#263957] rounded-lg text-slate-100 outline-none transition duration-200 hover:border-[#3b5278] focus:border-blue-400/80 focus:ring-2 focus:ring-blue-500/20"
                  />
                ))}
              </div>

              <button
                type="button"
                onClick={verifyOtp}
                disabled={loading || otp.join("").length !== 6}
                className="mt-4 w-full rounded-lg border border-[#263957] bg-[#101b30] px-3 py-2 text-xs font-semibold text-blue-200 transition duration-200 hover:bg-[#172844] disabled:cursor-not-allowed disabled:opacity-40"
              >
                {otpVerified ? "Code entered" : "Check Code"}
              </button>

              <p className="mt-2 text-xs leading-relaxed text-slate-500">
                The code will be validated by the server when you reset your
                password.
              </p>
            </div>

            {/* New Password */}
            <div>
              <label
                htmlFor="new-password"
                className="mb-2 block text-xs font-semibold uppercase tracking-wider text-slate-400"
              >
                New Password
              </label>

              <div className="relative">
                <input
                  id="new-password"
                  type={showPassword ? "text" : "password"}
                  autoComplete="new-password"
                  placeholder="Create a new password"
                  className={`${inputClass} pr-12`}
                  value={newPassword}
                  onChange={(event) => setNewPassword(event.target.value)}
                  required
                  minLength={8}
                />

                <button
                  type="button"
                  onClick={() => setShowPassword((visible) => !visible)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  className="absolute right-3 top-1/2 -translate-y-1/2 rounded-md p-1 text-slate-500 transition duration-200 hover:text-blue-200"
                >
                  {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
                </button>
              </div>

              <p className="mt-2 text-xs text-slate-500">
                Use at least 8 characters.
              </p>
            </div>

            {/* Confirm Password */}
            <div>
              <label
                htmlFor="confirm-password"
                className="mb-2 block text-xs font-semibold uppercase tracking-wider text-slate-400"
              >
                Confirm New Password
              </label>

              <div className="relative">
                <input
                  id="confirm-password"
                  type={showConfirmPassword ? "text" : "password"}
                  autoComplete="new-password"
                  placeholder="Re-enter your new password"
                  className={`${inputClass} pr-12`}
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
                  required
                  minLength={8}
                />

                <button
                  type="button"
                  onClick={() =>
                    setShowConfirmPassword((visible) => !visible)
                  }
                  aria-label={
                    showConfirmPassword
                      ? "Hide confirmation password"
                      : "Show confirmation password"
                  }
                  className="absolute right-3 top-1/2 -translate-y-1/2 rounded-md p-1 text-slate-500 transition duration-200 hover:text-blue-200"
                >
                  {showConfirmPassword ? (
                    <EyeOff size={17} />
                  ) : (
                    <Eye size={17} />
                  )}
                </button>
              </div>
            </div>

            {/* Submit */}
            <button
              type="submit"
              disabled={loading || resendLoading}
              className="flex w-full items-center justify-center gap-2 rounded-xl border border-blue-500/20 bg-blue-600/90 px-4 py-3 text-sm font-semibold text-white transition duration-200 hover:bg-blue-700/90 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? (
                <>
                  <Loader2 size={16} className="animate-spin" />
                  Resetting Password...
                </>
              ) : (
                "Reset Password"
              )}
            </button>

            {/* Resend Code */}
            <div className="text-center">
              {canResend ? (
                <button
                  type="button"
                  onClick={handleResend}
                  disabled={resendLoading || loading}
                  className="text-blue-200/80 hover:text-blue-100 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {resendLoading ? (
                    <span className="inline-flex items-center gap-2">
                      <Loader2 size={14} className="animate-spin" />
                      Sending Code...
                    </span>
                  ) : (
                    "Resend Code"
                  )}
                </button>
              ) : (
                <p className="text-sm text-slate-500">
                  Resend code in{" "}
                  <span className="font-medium tabular-nums text-slate-400">
                    {countdown}s
                  </span>
                </p>
              )}
            </div>
          </form>

          {/* Feedback */}
          {error && (
            <div
              role="alert"
              className="mt-5 rounded-xl border border-red-900/60 bg-red-950/30 px-4 py-3 text-sm text-red-300"
            >
              {error}
            </div>
          )}

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
              className="inline-flex items-center gap-2 text-xs font-medium text-blue-200/80 transition duration-200 hover:text-blue-100"
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

export default ResetPassword;