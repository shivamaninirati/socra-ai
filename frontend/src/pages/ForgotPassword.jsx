import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Shield, Loader2, ArrowLeft } from "lucide-react";
import api from "../services/api";

function ForgotPassword() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    setError("");
    setSuccess("");

    if (!email.trim()) {
      setError("Email is required.");
      return;
    }

    setLoading(true);
    try {
      const response = await api.post("/forgot-password", {
        email: email.trim().toLowerCase(),
      });

      if (response.data?.success) {
        setSuccess(response.data.message);
        // Navigate to reset password page after a brief delay
        setTimeout(() => {
          navigate("/reset-password", {
            state: { email: email.trim().toLowerCase() },
          });
        }, 1500);
      } else {
        setError(response.data?.error || "Failed to send reset code.");
      }
    } catch (err) {
      setError(
        err.response?.data?.error || "Failed to send reset code. Please try again."
      );
    } finally {
      setLoading(false);
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
              Forgot Password
            </h1>
            <p className="text-xs text-slate-500 mt-1.5 font-medium tracking-wider text-center">
              Enter your email to receive a reset code
            </p>
          </div>

          <div className="space-y-4">
            <div>
              <label className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1.5 block">
                Email Address
              </label>
              <input
                type="email"
                placeholder="Enter your email"
                className="w-full bg-slate-900/50 border border-slate-800 rounded-lg px-4 py-2.5 text-sm text-slate-200 placeholder:text-slate-600 outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/30 transition-all"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
              />
            </div>

            <button
              onClick={handleSubmit}
              disabled={loading}
              className="w-full bg-cyan-600 hover:bg-cyan-500 disabled:bg-cyan-600/50 text-white text-sm font-bold py-2.5 rounded-lg transition-all duration-150 flex items-center justify-center gap-2 mt-2"
            >
              {loading ? (
                <>
                  <Loader2 size={16} className="animate-spin" />
                  Sending...
                </>
              ) : (
                "Send Reset Code"
              )}
            </button>
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

export default ForgotPassword;
