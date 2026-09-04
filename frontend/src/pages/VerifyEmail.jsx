import { useState, useEffect, useRef } from "react";
import { useNavigate, useLocation, Link } from "react-router-dom";
import { Shield, Loader2, Mail, ArrowLeft } from "lucide-react";
import api from "../services/api";

function VerifyEmail() {
  const navigate = useNavigate();
  const location = useLocation();
  const email = location.state?.email || "";

  const [otp, setOtp] = useState(["", "", "", "", "", ""]);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);
  const [resendLoading, setResendLoading] = useState(false);
  const [countdown, setCountdown] = useState(60);
  const [canResend, setCanResend] = useState(false);
  const inputRefs = useRef([]);

  useEffect(() => {
    if (!email) {
      navigate("/register");
      return;
    }
    // Focus first input
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

    // Auto-advance to next input
    if (value && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }

    // Auto-submit when all digits entered
    if (newOtp.every((d) => d !== "") && newOtp.join("").length === 6) {
      verifyOtp(newOtp.join(""));
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
        verifyOtp(pasted);
      } else {
        inputRefs.current[Math.min(pasted.length, 5)]?.focus();
      }
    }
  };

  const verifyOtp = async (otpCode) => {
    setLoading(true);
    setError("");
    try {
      const response = await api.post("/verify-email", {
        email,
        otp: otpCode,
      });

      if (response.data?.success) {
        setSuccess("Email verified successfully! Redirecting to login...");
        setTimeout(() => navigate("/login"), 2000);
      } else {
        setError(response.data?.error || "Verification failed.");
        setOtp(["", "", "", "", "", ""]);
        inputRefs.current[0]?.focus();
      }
    } catch (err) {
      setError(
        err.response?.data?.error || "Verification failed. Please try again."
      );
      setOtp(["", "", "", "", "", ""]);
      inputRefs.current[0]?.focus();
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    setResendLoading(true);
    setError("");
    setSuccess("");
    try {
      const response = await api.post("/resend-verification", { email });
      if (response.data?.success) {
        setSuccess("A new verification code has been sent.");
        setCountdown(60);
        setCanResend(false);
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
            <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center mb-4">
              <Mail size={28} className="text-cyan-400" />
            </div>
            <h1 className="text-2xl font-bold text-white tracking-wide">
              Verify Email
            </h1>
            <p className="text-xs text-slate-500 mt-1.5 font-medium tracking-wider text-center">
              Enter the 6-digit code sent to
            </p>
            <p className="text-sm text-cyan-400 font-semibold mt-1">{email}</p>
          </div>

          <div className="space-y-6">
            {/* OTP Input */}
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
                  className="w-12 h-14 text-center text-xl font-bold bg-slate-900/50 border border-slate-800 rounded-lg text-slate-200 outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/30 transition-all"
                />
              ))}
            </div>

            {loading && (
              <div className="flex items-center justify-center gap-2 text-cyan-400 text-sm">
                <Loader2 size={16} className="animate-spin" />
                Verifying...
              </div>
            )}

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

            {/* Change email */}
            <div className="text-center">
              <Link
                to="/register"
                className="text-slate-500 hover:text-slate-300 text-xs inline-flex items-center gap-1"
              >
                <ArrowLeft size={12} />
                Change email
              </Link>
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
        </div>
      </div>
    </div>
  );
}

export default VerifyEmail;
