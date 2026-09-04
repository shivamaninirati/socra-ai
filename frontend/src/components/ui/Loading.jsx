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

/**
 * Premium SOCRA AI enterprise loading screen.
 *
 * Shows the real SOCRA AI logo with a subtle cyber glow, radar sweep,
 * rotating dashed ring, and cycling status messages. Fades to "SYSTEM READY"
 * once `ready` prop becomes true, then calls `onComplete` after the
 * fade-out animation finishes.
 *
 * `ready` should be set by the parent when initialization is genuinely
 * complete (auth check, initial API fetch, etc.) — never an arbitrary delay.
 */
function Loading({ ready = false, onComplete }) {
  const [msgIndex, setMsgIndex] = useState(0);
  const [phase, setPhase] = useState("loading"); // 'loading' | 'ready' | 'done'
  const fadeTimerRef = useRef(null);
  const completeTimerRef = useRef(null);

  // Cycle through status messages while in loading phase
  useEffect(() => {
    if (phase !== "loading") return;
    const id = setInterval(() => {
      setMsgIndex((i) => (i + 1) % STATUS_MESSAGES.length);
    }, CYCLE_INTERVAL_MS);
    return () => clearInterval(id);
  }, [phase]);

  // When `ready` becomes true, transition to SYSTEM READY then call onComplete
  useEffect(() => {
    if (!ready || phase !== "loading") return;

    setPhase("ready");
    fadeTimerRef.current = setTimeout(() => {
      setPhase("done");
      completeTimerRef.current = setTimeout(() => {
        onComplete?.();
      }, 700); // matches socra-fade-out animation duration
    }, 1200);

    return () => {
      clearTimeout(fadeTimerRef.current);
      clearTimeout(completeTimerRef.current);
    };
  }, [ready, phase, onComplete]);

  // If phase is "done" and no onComplete, just render nothing
  if (phase === "done" && !onComplete) return null;

  const displayMessage =
    phase === "ready" ? "SYSTEM READY" : STATUS_MESSAGES[msgIndex];

  return (
    <div
      className={[
        "fixed inset-0 z-[100] flex flex-col items-center justify-center",
        "bg-slate-950",
        phase === "done" ? "socra-loading-overlay" : "",
      ].join(" ")}
    >
      {/* Ambient background radial glow */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] rounded-full bg-cyan-500/[0.03] blur-[100px]" />
      </div>

      {/* Logo container with all animation layers */}
      <div className="relative w-[200px] h-[200px] socra-logo-enter">
        {/* Layer 1: Outer pulsing glow */}
        <div
          className="absolute inset-[-20px] rounded-full"
          style={{
            background:
              "radial-gradient(circle, rgba(6,182,212,0.15) 0%, transparent 70%)",
            animation: "socra-pulse-glow 3s ease-in-out infinite",
          }}
        />

        {/* Layer 2: Radar sweep — conic-gradient rotating clockwise */}
        <div
          className="absolute top-1/2 left-1/2 w-[180px] h-[180px] rounded-full overflow-hidden"
          style={{
            transform: "translate(-50%, -50%)",
            animation: "socra-radar-sweep 4s linear infinite",
          }}
        >
          <div
            className="absolute inset-0"
            style={{
              background:
                "conic-gradient(from 0deg, transparent 0deg, rgba(6,182,212,0.18) 30deg, transparent 60deg)",
            }}
          />
        </div>

        {/* Layer 3: Rotating dashed ring */}
        <svg
          className="absolute top-1/2 left-1/2 w-[170px] h-[170px]"
          style={{
            transform: "translate(-50%, -50%)",
            animation: "socra-ring-rotate 20s linear infinite",
          }}
          viewBox="0 0 170 170"
        >
          <circle
            cx="85"
            cy="85"
            r="80"
            fill="none"
            stroke="rgba(6,182,212,0.12)"
            strokeWidth="1"
            strokeDasharray="8 12"
          />
        </svg>

        {/* Layer 4: Inner thin ring (counter-rotating) */}
        <svg
          className="absolute top-1/2 left-1/2 w-[130px] h-[130px]"
          style={{
            transform: "translate(-50%, -50%)",
            animation: "socra-ring-rotate 30s linear infinite reverse",
          }}
          viewBox="0 0 130 130"
        >
          <circle
            cx="65"
            cy="65"
            r="62"
            fill="none"
            stroke="rgba(6,182,212,0.08)"
            strokeWidth="0.5"
            strokeDasharray="3 8"
          />
        </svg>

        {/* Layer 5: Horizontal scan line */}
        <div
          className="absolute top-1/2 left-1/2 w-[160px] h-[1px] -translate-x-1/2"
          style={{
            background:
              "linear-gradient(90deg, transparent, rgba(6,182,212,0.4), transparent)",
            animation: "socra-scan-line 3s ease-in-out infinite",
          }}
        />

        {/* Layer 6: SOCRA AI logo */}
        <div className="absolute inset-0 flex items-center justify-center">
          <div
            className="w-[110px] h-[110px] rounded-full flex items-center justify-center"
            style={{
              background:
                "radial-gradient(circle, rgba(6,182,212,0.08) 0%, transparent 70%)",
            }}
          >
            <img
              src={socraLogo}
              alt="SOCRA AI"
              className="w-[90px] h-[90px] object-contain select-none"
              draggable={false}
              style={{
                filter: "drop-shadow(0 0 20px rgba(6,182,212,0.3))",
                animation: "socra-pulse-glow 3s ease-in-out infinite",
              }}
            />
          </div>
        </div>
      </div>

      {/* Text: SOCRA AI */}
      <h1 className="socra-text-enter mt-8 text-2xl font-bold tracking-[0.2em] text-white select-none">
        SOCRA AI
      </h1>

      {/* Text: Subtitle */}
      <p className="socra-subtext-enter mt-2 text-[10px] font-semibold uppercase tracking-[0.3em] text-slate-500 select-none">
        Security Investigation Platform
      </p>

      {/* Status message with smooth crossfade */}
      <div className="socra-status-enter mt-8 h-5 flex items-center justify-center">
        <p
          key={displayMessage}
          className={[
            "text-xs font-medium tracking-wide",
            phase === "ready" ? "text-emerald-400" : "text-slate-400",
          ].join(" ")}
          style={{
            animation: "socra-fade-in 0.4s ease-out forwards",
          }}
        >
          {phase === "ready" ? (
            <span className="flex items-center gap-2">
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400" />
              {displayMessage}
            </span>
          ) : (
            <>
              {displayMessage}
              <span className="inline-flex w-4 ml-0.5">
                <span style={{ animation: "socra-dot-blink 1.4s infinite 0s" }}>.</span>
                <span style={{ animation: "socra-dot-blink 1.4s infinite 0.2s" }}>.</span>
                <span style={{ animation: "socra-dot-blink 1.4s infinite 0.4s" }}>.</span>
              </span>
            </>
          )}
        </p>
      </div>

      {/* Progress bar */}
      {phase === "loading" && (
        <div className="mt-6 w-48 h-[2px] rounded-full bg-slate-800 overflow-hidden">
          <div
            className="h-full rounded-full socra-progress-bar"
            style={{
              background:
                "linear-gradient(90deg, rgba(6,182,212,0.2), rgba(6,182,212,0.6), rgba(6,182,212,0.2))",
              backgroundSize: "200% 100%",
            }}
          />
        </div>
      )}

      {/* Version tag */}
      <p className="absolute bottom-6 text-[9px] font-medium tracking-wider text-slate-700 uppercase select-none">
        v0.1.0 — Enterprise Edition
      </p>
    </div>
  );
}

export default Loading;