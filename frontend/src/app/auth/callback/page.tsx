"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";

import { exchangeOidcToken, setOidcToken } from "@/auth/oidcAuth";

export default function OidcCallbackPage() {
  const searchParams = useSearchParams();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const sessionId = searchParams.get("session_id");
    const errorParam = searchParams.get("error");

    if (errorParam) {
      setError("Authentication was denied or failed. Please try again.");
      return;
    }

    if (!sessionId) {
      setError("Missing session token. Please try signing in again.");
      return;
    }

    let cancelled = false;

    async function doExchange() {
      const token = await exchangeOidcToken(sessionId!);
      if (cancelled) return;

      if (!token) {
        setError(
          "Failed to complete sign-in. The link may have expired — please try again.",
        );
        return;
      }

      setOidcToken(token);

      // Navigate to the app — use replace so the callback URL (with the
      // one-time token) doesn't stay in browser history.
      window.location.replace("/onboarding");
    }

    doExchange();

    return () => {
      cancelled = true;
    };
  }, [searchParams]);

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-app px-4">
        <div className="w-full max-w-md rounded-xl border border-red-200 bg-red-50 px-6 py-5 text-center">
          <p className="text-sm font-medium text-red-800">{error}</p>
          <button
            onClick={() => window.location.replace("/")}
            className="mt-4 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700"
          >
            Try again
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-app">
      <p className="text-sm text-muted">Completing sign-in…</p>
    </div>
  );
}
