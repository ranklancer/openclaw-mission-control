"use client";

import { AuthMode } from "@/auth/mode";

let oidcToken: string | null = null;
const STORAGE_KEY = "mc_oidc_session_token";

export function isOidcAuthMode(): boolean {
  return process.env.NEXT_PUBLIC_AUTH_MODE === AuthMode.Oidc;
}

export function setOidcToken(token: string): void {
  oidcToken = token;
  if (typeof window === "undefined") return;
  try {
    window.sessionStorage.setItem(STORAGE_KEY, token);
  } catch {
    // Ignore storage failures (private mode / policy).
  }
}

export function getOidcToken(): string | null {
  if (oidcToken) return oidcToken;
  if (typeof window === "undefined") return null;
  try {
    const stored = window.sessionStorage.getItem(STORAGE_KEY);
    if (stored) {
      oidcToken = stored;
      return stored;
    }
  } catch {
    // Ignore storage failures (private mode / policy).
  }
  return null;
}

export function clearOidcToken(): void {
  oidcToken = null;
  if (typeof window === "undefined") return;
  try {
    window.sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // Ignore storage failures (private mode / policy).
  }
}

/**
 * Redirect the browser to the backend's OIDC login endpoint,
 * which initiates the Authorization Code flow with the provider.
 */
export function redirectToOidcLogin(): void {
  if (typeof window === "undefined") return;
  const apiBaseUrl = process.env.NEXT_PUBLIC_API_URL?.trim()?.replace(/\/+$/, "");
  if (!apiBaseUrl || apiBaseUrl.toLowerCase() === "auto") {
    // Fallback: same origin, port 8000
    const protocol = window.location.protocol;
    const host = window.location.hostname;
    window.location.href = `${protocol}//${host}:8000/api/v1/auth/oidc/login`;
    return;
  }
  window.location.href = `${apiBaseUrl}/api/v1/auth/oidc/login`;
}

/**
 * Exchange a one-time session_id (from the OIDC callback redirect)
 * for a backend-signed session JWT.
 */
export async function exchangeOidcToken(
  sessionId: string,
): Promise<string | null> {
  let apiBaseUrl: string;
  try {
    const raw = process.env.NEXT_PUBLIC_API_URL?.trim();
    if (raw && raw.toLowerCase() !== "auto") {
      apiBaseUrl = raw.replace(/\/+$/, "");
    } else if (typeof window !== "undefined") {
      const protocol = window.location.protocol === "https:" ? "https" : "http";
      apiBaseUrl = `${protocol}://${window.location.hostname}:8000`;
    } else {
      return null;
    }
  } catch {
    return null;
  }

  try {
    const response = await fetch(`${apiBaseUrl}/api/v1/auth/oidc/exchange`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id: sessionId }),
    });

    if (!response.ok) return null;

    const data = (await response.json()) as { token?: string };
    return data.token ?? null;
  } catch {
    return null;
  }
}
