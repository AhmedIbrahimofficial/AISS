"use client";
import { useState } from "react";
import { Mail, RefreshCw, CheckCircle, LogOut } from "lucide-react";
import Link from "next/link";
import { getAccessToken, clearTokens, saveTokens } from "../lib/auth";

export default function VerifyPendingPage() {
  const [resent,   setResent]   = useState(false);
  const [loading,  setLoading]  = useState(false);
  const [checking, setChecking] = useState(false);
  const [verified, setVerified] = useState(false);

  async function resendEmail() {
    setLoading(true);
    const token = getAccessToken();
    try {
      await fetch("http://localhost:8000/api/auth/resend-verification", {
        method:  "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      setResent(true);
    } finally {
      setLoading(false);
    }
  }

  async function checkVerification() {
    setChecking(true);
    const token = getAccessToken();
    try {
      const res     = await fetch("http://localhost:8000/api/auth/me", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const profile = await res.json();

      if (profile.is_verified) {
        // Update stored tokens with verified=true (7 day cookies)
        const refresh = localStorage.getItem("refresh_token") || "";
        saveTokens(token, refresh, true);
        setVerified(true);
        setTimeout(() => {
          const params  = new URLSearchParams(window.location.search);
          window.location.href = params.get("next") || "/dashboard";
        }, 1500);
      } else {
        alert("Email not verified yet. Please check your inbox.");
      }
    } finally {
      setChecking(false);
    }
  }

  function logout() {
    clearTokens();
    window.location.href = "/login";
  }

  if (verified) {
    return (
      <main className="bg-black min-h-screen flex items-center justify-center px-4 pt-16">
        <div className="text-center">
          <CheckCircle size={48} className="text-neon mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-white mb-2">Email Verified!</h2>
          <p className="text-white/40">Redirecting you now...</p>
        </div>
      </main>
    );
  }

  return (
    <main className="bg-black min-h-screen flex items-center justify-center px-4 pt-16">

      <div className="fixed inset-0 pointer-events-none"
        style={{
          backgroundImage: `linear-gradient(rgba(0,255,136,0.03) 1px, transparent 1px),
                            linear-gradient(90deg, rgba(0,255,136,0.03) 1px, transparent 1px)`,
          backgroundSize: "40px 40px",
        }}
      />

      <div className="relative w-full max-w-md text-center">

        <div className="cyber-card p-10">
          {/* Icon */}
          <div className="w-20 h-20 rounded-full bg-neon/10 border border-neon/20 flex items-center justify-center mx-auto mb-6">
            <Mail size={36} className="text-neon" />
          </div>

          <h1 className="text-2xl font-bold text-white mb-3">
            Verify your email
          </h1>
          <p className="text-white/50 text-sm leading-relaxed mb-8">
            We sent a verification link to your email address.
            Click the link to activate your account and access all features.
          </p>

          {/* Steps */}
          <div className="text-left space-y-3 mb-8">
            {[
              "Open your email inbox",
              'Find the email from "CyberSec Platform"',
              'Click "Verify Email" button',
              "Come back and click Check Status below",
            ].map((step, i) => (
              <div key={i} className="flex items-start gap-3">
                <span className="w-5 h-5 rounded-full bg-neon/20 border border-neon/30 flex items-center justify-center text-neon text-xs font-bold shrink-0 mt-0.5">
                  {i + 1}
                </span>
                <span className="text-white/60 text-sm">{step}</span>
              </div>
            ))}
          </div>

          {/* Actions */}
          <div className="space-y-3">
            <button
              onClick={checkVerification}
              disabled={checking}
              className="btn-neon-solid w-full py-3 flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {checking ? (
                <span className="w-4 h-4 border-2 border-black/30 border-t-black rounded-full animate-spin" />
              ) : (
                <CheckCircle size={16} />
              )}
              {checking ? "Checking..." : "I verified — Check Status"}
            </button>

            <button
              onClick={resendEmail}
              disabled={loading || resent}
              className="btn-neon w-full py-3 flex items-center justify-center gap-2 disabled:opacity-50"
            >
              <RefreshCw size={16} className={loading ? "animate-spin" : ""} />
              {resent ? "Email sent!" : loading ? "Sending..." : "Resend verification email"}
            </button>
          </div>

          {resent && (
            <p className="text-neon text-xs mt-3">
              ✓ Verification email resent. Check your spam folder too.
            </p>
          )}

          <button
            onClick={logout}
            className="mt-6 flex items-center gap-2 text-white/30 hover:text-white/60 text-xs mx-auto transition-colors"
          >
            <LogOut size={12} />
            Sign out and use different account
          </button>
        </div>

      </div>
    </main>
  );
}
