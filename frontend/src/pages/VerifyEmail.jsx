import { useState, useEffect, useRef } from "react";
import { useNavigate, useLocation, Link } from "react-router-dom";
import { Loader2, Mail, ArrowLeft } from "lucide-react";
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
          <div className="flex flex-col items-center mb-6 text-center">
            <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-2xl border border-blue-400/20 bg-gradient-to-br from-[#172844] to-[#0d172b] shadow-lg shadow-blue-950/30">
              <Mail size={26} strokeWidth={1.8} className="text-blue-200" />
            </div>
            <h1 className="text-2xl font-bold tracking-wide text-white">
              Verify Email
            </h1>
            <p className="mt-2 text-center text-[11px] font-medium uppercase tracking-[0.2em] text-blue-200/55">
              Enter the code sent to your email
            </p>
            <div className="mt-4 h-px w-16 bg-gradient-to-r from-transparent via-blue-400/50 to-transparent" />
            <p className="mt-3 max-w-full break-all text-sm font-medium text-blue-200">{email}</p>
          </div>

          <div className="space-y-4">
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
                  className="w-12 h-14 text-center text-xl font-bold bg-[#101b30] border border-[#263957] rounded-lg text-slate-100 outline-none transition duration-200 hover:border-[#3b5278] focus:border-blue-400/80 focus:ring-2 focus:ring-blue-500/20"
                />
              ))}
            </div>

            {loading && (
              <div className="flex items-center justify-center gap-2 text-blue-200 text-sm">
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
                  className="text-blue-200/80 hover:text-blue-100 text-sm font-semibold disabled:opacity-50"
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
                className="text-slate-500 hover:text-blue-200 text-xs inline-flex items-center gap-1 transition"
              >
                <ArrowLeft size={12} />
                Change email
              </Link>
            </div>
          </div>

          <div className="mt-5 border-t border-[#202d45] pt-4 text-center">
            <p className="text-sm text-slate-400">
              Already verified?{" "}
              <Link
                to="/login"
                className="font-semibold text-blue-200 transition hover:text-white"
              >
                Sign in
              </Link>
            </p>
          </div>

          {error && (
            <div className="mt-4 rounded-lg border border-red-500/25 bg-red-500/10 px-4 py-3 text-sm text-red-300 text-center">
              {error}
            </div>
          )}

          {success && (
            <div className="mt-4 rounded-lg border border-green-500/25 bg-green-500/10 px-4 py-3 text-sm text-green-300 text-center">
              {success}
            </div>
          )}
        </div>
        <p className="mt-5 text-center text-[10px] font-medium uppercase tracking-[0.18em] text-slate-500/80">
          SOCRA AI · Security Operations
        </p>
      </div>
    </div>
  );
}

export default VerifyEmail;