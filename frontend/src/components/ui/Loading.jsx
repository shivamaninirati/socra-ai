import { useState, useEffect, useRef } from "react";
import socraLogo from "../../assets/socra-logo.png";

const STATUS_MESSAGES = [
  "Initializing SOCRA AI...",
  "Connecting to security services...",
  "Loading telemetry...",
  "Initializing threat intelligence...",
  "Establishing secure session...",
];

const CYCLE_INTERVAL_MS = 2200;

function Loading({ ready = false, onComplete }) {
  const [msgIndex, setMsgIndex] = useState(0);
  const [phase, setPhase] = useState("loading");

  const fadeTimerRef = useRef(null);
  const completeTimerRef = useRef(null);

  useEffect(() => {
    if (phase !== "loading") return;

    const id = setInterval(() => {
      setMsgIndex((index) => (index + 1) % STATUS_MESSAGES.length);
    }, CYCLE_INTERVAL_MS);

    return () => clearInterval(id);
  }, [phase]);

  useEffect(() => {
    if (!ready || phase !== "loading") return;

    setPhase("ready");

    fadeTimerRef.current = setTimeout(() => {
      setPhase("done");

      completeTimerRef.current = setTimeout(() => {
        onComplete?.();
      }, 700);
    }, 1200);

    return () => {
      clearTimeout(fadeTimerRef.current);
      clearTimeout(completeTimerRef.current);
    };
  }, [ready, phase, onComplete]);

  useEffect(() => {
    return () => {
      clearTimeout(fadeTimerRef.current);
      clearTimeout(completeTimerRef.current);
    };
  }, []);

  if (phase === "done" && !onComplete) return null;

  const displayMessage =
    phase === "ready" ? "SYSTEM READY" : STATUS_MESSAGES[msgIndex];

  return (
    <div
      className={[
        "fixed inset-0 z-[100] flex flex-col items-center justify-center",
        "overflow-hidden bg-slate-950",
        phase === "done" ? "socra-loading-overlay" : "",
      ].join(" ")}
    >
      {/* Ambient background */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute left-1/2 top-1/2 h-[600px] w-[600px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-slate-500/[0.04] blur-[120px]" />

        <div
          className="absolute inset-0 opacity-[0.035]"
          style={{
            backgroundImage:
              "linear-gradient(rgba(148,163,184,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.3) 1px, transparent 1px)",
            backgroundSize: "48px 48px",
            maskImage:
              "radial-gradient(ellipse at center, black 0%, transparent 75%)",
            WebkitMaskImage:
              "radial-gradient(ellipse at center, black 0%, transparent 75%)",
          }}
        />
      </div>

      {/* Animated logo system */}
      <div className="socra-logo-enter relative h-[200px] w-[200px]">
        {/* Outer ambient glow */}
        <div
          className="absolute inset-[-20px] rounded-full"
          style={{
            background:
              "radial-gradient(circle, rgba(148,163,184,0.09) 0%, transparent 70%)",
            animation: "socra-pulse-glow 3s ease-in-out infinite",
          }}
        />

        {/* Radar sweep */}
        <div
          className="absolute left-1/2 top-1/2 h-[180px] w-[180px] overflow-hidden rounded-full"
          style={{
            transform: "translate(-50%, -50%)",
            animation: "socra-radar-sweep 4s linear infinite",
          }}
        >
          <div
            className="absolute inset-0"
            style={{
              background:
                "conic-gradient(from 0deg, transparent 0deg, rgba(148,163,184,0.12) 30deg, transparent 60deg)",
            }}
          />
        </div>

        {/* Outer rotating ring */}
        <svg
          className="absolute left-1/2 top-1/2 h-[170px] w-[170px]"
          style={{
            transform: "translate(-50%, -50%)",
            animation: "socra-ring-rotate 20s linear infinite",
          }}
          viewBox="0 0 170 170"
          aria-hidden="true"
        >
          <circle
            cx="85"
            cy="85"
            r="80"
            fill="none"
            stroke="rgba(148,163,184,0.18)"
            strokeWidth="1"
            strokeDasharray="8 12"
          />
        </svg>

        {/* Inner counter-rotating ring */}
        <svg
          className="absolute left-1/2 top-1/2 h-[130px] w-[130px]"
          style={{
            transform: "translate(-50%, -50%)",
            animation: "socra-ring-rotate 30s linear infinite reverse",
          }}
          viewBox="0 0 130 130"
          aria-hidden="true"
        >
          <circle
            cx="65"
            cy="65"
            r="62"
            fill="none"
            stroke="rgba(148,163,184,0.12)"
            strokeWidth="0.5"
            strokeDasharray="3 8"
          />
        </svg>

        {/* Horizontal scan line */}
        <div
          className="absolute left-1/2 top-1/2 h-px w-[160px] -translate-x-1/2"
          style={{
            background:
              "linear-gradient(90deg, transparent, rgba(148,163,184,0.35), transparent)",
            animation: "socra-scan-line 3s ease-in-out infinite",
          }}
        />

        {/* Logo */}
        <div className="absolute inset-0 flex items-center justify-center">
          <div
            className="flex h-[110px] w-[110px] items-center justify-center rounded-full"
            style={{
              background:
                "radial-gradient(circle, rgba(148,163,184,0.06) 0%, transparent 70%)",
            }}
          >
            <img
              src={socraLogo}
              alt="SOCRA AI"
              draggable={false}
              className="h-[90px] w-[90px] select-none object-contain"
              style={{
                filter:
                  "drop-shadow(0 0 16px rgba(100,116,139,0.2))",
                animation: "socra-pulse-glow 3s ease-in-out infinite",
              }}
            />
          </div>
        </div>
      </div>

      {/* Brand title */}
      <h1 className="socra-text-enter mt-8 select-none text-2xl font-bold tracking-[0.2em] text-white">
        SOCRA AI
      </h1>

      {/* Subtitle */}
      <p className="socra-subtext-enter mt-2 select-none text-[10px] font-semibold uppercase tracking-[0.3em] text-slate-500">
        Security Investigation Platform
      </p>

      {/* Status */}
      <div className="socra-status-enter mt-8 flex h-5 items-center justify-center">
        <p
          key={displayMessage}
          className={[
            "text-xs font-medium tracking-wide",
            phase === "ready" ? "text-emerald-400" : "text-slate-400",
          ].join(" ")}
          style={{
            animation: "socra-fade-in 0.4s ease-out forwards",
          }}
          aria-live="polite"
        >
          {phase === "ready" ? (
            <span className="flex items-center gap-2">
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-400" />
              {displayMessage}
            </span>
          ) : (
            <>
              {displayMessage}
              <span className="ml-0.5 inline-flex w-4">
                <span
                  style={{
                    animation: "socra-dot-blink 1.4s infinite 0s",
                  }}
                >
                  .
                </span>
                <span
                  style={{
                    animation: "socra-dot-blink 1.4s infinite 0.2s",
                  }}
                >
                  .
                </span>
                <span
                  style={{
                    animation: "socra-dot-blink 1.4s infinite 0.4s",
                  }}
                >
                  .
                </span>
              </span>
            </>
          )}
        </p>
      </div>

      {/* Progress bar */}
      {phase === "loading" && (
        <div className="mt-6 h-[2px] w-48 overflow-hidden rounded-full bg-slate-800">
          <div
            className="socra-progress-bar h-full rounded-full"
            style={{
              background:
                "linear-gradient(90deg, rgba(148,163,184,0.15), rgba(148,163,184,0.6), rgba(148,163,184,0.15))",
              backgroundSize: "200% 100%",
            }}
          />
        </div>
      )}

      {/* Version */}
      <p className="absolute bottom-6 select-none text-[9px] font-medium uppercase tracking-wider text-slate-700">
        v0.1.0 — Enterprise Edition
      </p>
    </div>
  );
}

export default Loading;