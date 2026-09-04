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
      navigate("/forgot-password");
      return;
    }
    inputRefs.current[0]?.focus();
  }, [email, navigate]);

  useEffect(() => {
    if (countdown > 0) {
      const timer = setTimeout(() => setCountdown(countdown - 1), 1000);
      return () => clearTimeout(timer);
    } else {
      setCanResend(true);
    }
  }, [countdown]);

  const handleOtpChange = (index, value) => {
    if (!/^\d*$/.test(value)) return;

    const newOtp = [...otp];
    newOtp[index] = value.slice(-1);
    setOtp(newOtp);
    setError("");

    if (value && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handleKeyDown = (index, e) => {
    if (e.key === "Backspace" && !otp[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
  };

  const handlePaste = (e) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, 6);
    if (pasted) {
      const newOtp = pasted.split("").concat(Array(6).fill("")).slice(0, 6);
      setOtp(newOtp);
      if (pasted.length === 6) {
        inputRefs.current[5]?.focus();
      } else {
        inputRefs.current[Math.min(pasted.length, 5)]?.focus();
      }
    }
  };

  const verifyOtp = async () => {
    const otpCode = otp.join("");
    if (otpCode.length !== 6) {
      setError("Please enter the complete 6-digit code.");
      return;
    }

    setLoading(true);
    setError("");
    try {
      // We verify the OTP as part of the reset process
      // For now, mark as verified - actual verification happens with password
      setOtpVerified(true);
    } catch (err) {
      setError("Invalid verification code.");
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async () => {
    setError("");

    if (!otpVerified) {
      setError("Please verify the OTP code first.");
      return;
    }

    const otpCode = otp.join("");
    if (otpCode.length !== 6) {
      setError("Please enter the complete 6-digit code.");
      return;
    }

    if (!newPassword) {
      setError("New password is required.");
      return;
    }

    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    if (newPassword.length < 8) {
      setError("Password must be at least 8 characters.");
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
        setTimeout(() => navigate("/login"), 2000);
      } else {
        setError(response.data?.error || "Password reset failed.");
      }
    } catch (err) {
      setError(
        err.response?.data?.error || "Password reset failed. Please try again."
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
        setCountdown(60);
        setCanResend(false);
        setOtpVerified(false);
      } else {
        setError(response.data?.error || "Failed to resend code.");
      }
    } catch (err) {
      setError(err.response?.data?.error || "Failed to resend code.");
    } finally {
      setResendLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-slate-950">
      <div className="w-full max-w-md px-4">
        <div className="bg-slate-800/40 border border-slate-700/60 rounded-2xl p-8 shadow-2xl shadow-black/40">
          <div className="flex flex-col items-center mb-8">
            <div className="w-14 h-14 rounded-2xl bg-red-500/10 border border-red-500/20 flex items-center justify-center mb-4">
              <Shield size={28} className="text-red-400" />
            </div>
            <h1 className="text-2xl font-bold text-white tracking-wide">
              Reset Password
            </h1>
            <p className="text-xs text-slate-500 mt-1.5 font-medium tracking-wider text-center">
              Enter the code and create a new password
            </p>
            <p className="text-sm text-cyan-400 font-semibold mt-1">{email}</p>
          </div>

          <div className="space-y-5">
            {/* OTP Input */}
            <div>
              <label className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-2 block">
                Verification Code
              </label>
              <div className="flex justify-center gap-2">
                {otp.map((digit, index) => (
                  <input
                    key={index}
                    ref={(el) => (inputRefs.current[index] = el)}
                    type="text"
                    inputMode="numeric"
                    maxLength={1}
                    value={digit}
                    onChange={(e) => handleOtpChange(index, e.target.value)}
                    onKeyDown={(e) => handleKeyDown(index, e)}
                    onPaste={handlePaste}
                    className="w-10 h-12 text-center text-lg font-bold bg-slate-900/50 border border-slate-800 rounded-lg text-slate-200 outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/30 transition-all"
                  />
                ))}
              </div>
            </div>

            {/* New Password */}
            <div>
              <label className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1.5 block">
                New Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  placeholder="Create a strong password"
                  className="w-full bg-slate-900/50 border border-slate-800 rounded-lg px-4 py-2.5 pr-10 text-sm text-slate-200 placeholder:text-slate-600 outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/30 transition-all"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
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

            {/* Confirm Password */}
            <div>
              <label className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1.5 block">
                Confirm New Password
              </label>
              <input
                type="password"
                placeholder="Confirm your new password"
                className="w-full bg-slate-900/50 border border-slate-800 rounded-lg px-4 py-2.5 text-sm text-slate-200 placeholder:text-slate-600 outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/30 transition-all"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleResetPassword()}
              />
            </div>

            <button
              onClick={handleResetPassword}
              disabled={loading}
              className="w-full bg-cyan-600 hover:bg-cyan-500 disabled:bg-cyan-600/50 text-white text-sm font-bold py-2.5 rounded-lg transition-all duration-150 flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <Loader2 size={16} className="animate-spin" />
                  Resetting...
                </>
              ) : (
                "Reset Password"
              )}
            </button>

            {/* Resend */}
            <div className="text-center">
              {canResend ? (
                <button
                  onClick={handleResend}
                  disabled={resendLoading}
                  className="text-cyan-400 hover:text-cyan-300 text-sm font-semibold disabled:opacity-50"
                >
                  {resendLoading ? "Sending..." : "Resend Code"}
                </button>
              ) : (
                <p className="text-slate-500 text-sm">
                  Resend code in {countdown}s
                </p>
              )}
            </div>
          </div>

          {error && (
            <div className="mt-4 rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-2.5 text-xs text-red-300 text-center">
              {error}
            </div>
          )}

          {success && (
            <div className="mt-4 rounded-lg border border-green-500/20 bg-green-500/10 px-4 py-2.5 text-xs text-green-300 text-center">
              {success}
            </div>
          )}

          <div className="mt-6 text-center">
            <Link
              to="/login"
              className="text-slate-500 hover:text-slate-300 text-xs inline-flex items-center gap-1"
            >
              <ArrowLeft size={12} />
              Back to Sign In
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ResetPassword;
