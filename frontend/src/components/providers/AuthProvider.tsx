"use client";

import { ClerkProvider } from "@clerk/nextjs";
import { useEffect, useState, type ReactNode } from "react";

import { isLikelyValidClerkPublishableKey } from "@/auth/clerkKey";
import {
  clearLocalAuthToken,
  getLocalAuthToken,
  isLocalAuthMode,
} from "@/auth/localAuth";
import {
  clearOidcToken,
  getOidcToken,
  isOidcAuthMode,
  redirectToOidcLogin,
} from "@/auth/oidcAuth";
import { LocalAuthLogin } from "@/components/organisms/LocalAuthLogin";

/** Returns true when the browser is on the OIDC callback page. */
function isOidcCallbackPath(): boolean {
  if (typeof window === "undefined") return false;
  return window.location.pathname === "/auth/callback";
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const localMode = isLocalAuthMode();
  const oidcMode = isOidcAuthMode();

  useEffect(() => {
    if (!localMode) {
      clearLocalAuthToken();
    }
    if (!oidcMode) {
      clearOidcToken();
    }
  }, [localMode, oidcMode]);

  // --- Local auth: show token prompt ---
  if (localMode) {
    if (!getLocalAuthToken()) {
      return <LocalAuthLogin />;
    }
    return <>{children}</>;
  }

  // --- OIDC auth: redirect to provider if no session token ---
  if (oidcMode) {
    // Allow the /auth/callback page to render without a token — it
    // performs the one-time exchange that *creates* the token.
    if (!getOidcToken() && !isOidcCallbackPath()) {
      // Not yet authenticated — redirect to OIDC login.
      // We do this in an effect to avoid hydration mismatches.
      return <OidcRedirect />;
    }
    return <>{children}</>;
  }

  // --- Clerk auth ---
  const publishableKey = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;
  const afterSignOutUrl =
    process.env.NEXT_PUBLIC_CLERK_AFTER_SIGN_OUT_URL ?? "/";

  if (!isLikelyValidClerkPublishableKey(publishableKey)) {
    return <>{children}</>;
  }

  return (
    <ClerkProvider
      publishableKey={publishableKey}
      afterSignOutUrl={afterSignOutUrl}
    >
      {children}
    </ClerkProvider>
  );
}

/** Minimal component that redirects to the OIDC login endpoint. */
function OidcRedirect() {
  useEffect(() => {
    redirectToOidcLogin();
  }, []);

  return (
    <div className="flex min-h-screen items-center justify-center bg-app">
      <p className="text-sm text-muted">Redirecting to sign in…</p>
    </div>
  );
}
