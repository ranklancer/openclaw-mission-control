import { getLocalAuthToken, isLocalAuthMode } from "@/auth/localAuth";
import { getOidcToken, isOidcAuthMode } from "@/auth/oidcAuth";
import { getApiBaseUrl } from "@/lib/api-base";

type ClerkSession = {
  getToken: () => Promise<string>;
};

type ClerkGlobal = {
  session?: ClerkSession | null;
};

export class ApiError<TData = unknown> extends Error {
  status: number;
  data: TData | null;

  constructor(status: number, message: string, data: TData | null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.data = data;
  }
}

const resolveClerkToken = async (): Promise<string | null> => {
  if (typeof window === "undefined") {
    return null;
  }
  const clerk = (window as unknown as { Clerk?: ClerkGlobal }).Clerk;
  if (!clerk?.session) {
    return null;
  }
  try {
    return await clerk.session.getToken();
  } catch {
    return null;
  }
};

export const customFetch = async <T>(
  url: string,
  options: RequestInit,
): Promise<T> => {
  const baseUrl = getApiBaseUrl();

  const headers = new Headers(options.headers);
  const hasBody = options.body !== undefined && options.body !== null;
  if (hasBody && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  // Attach auth token: local → OIDC → Clerk (in priority order)
  if (isLocalAuthMode() && !headers.has("Authorization")) {
    const token = getLocalAuthToken();
    if (token) {
      headers.set("Authorization", `Bearer ${token}`);
    }
  }
  if (isOidcAuthMode() && !headers.has("Authorization")) {
    const token = getOidcToken();
    if (token) {
      headers.set("Authorization", `Bearer ${token}`);
    }
  }
  if (!headers.has("Authorization")) {
    const token = await resolveClerkToken();
    if (token) {
      headers.set("Authorization", `Bearer ${token}`);
    }
  }

  const response = await fetch(`${baseUrl}${url}`, {
    ...options,
    headers,
  });

  // If we get a 401 in OIDC mode, clear the stale token and redirect to login.
  if (response.status === 401 && isOidcAuthMode()) {
    const { clearOidcToken, redirectToOidcLogin } = await import(
      "@/auth/oidcAuth"
    );
    clearOidcToken();
    redirectToOidcLogin();
    // Return a rejected promise so callers don't proceed.
    throw new ApiError(401, "Session expired — redirecting to sign in.", null);
  }

  if (!response.ok) {
    const contentType = response.headers.get("content-type") ?? "";
    let errorData: unknown = null;
    const isJson =
      contentType.includes("application/json") || contentType.includes("+json");
    if (isJson) {
      errorData = (await response.json().catch(() => null)) as unknown;
    } else {
      errorData = await response.text().catch(() => "");
    }

    let message =
      typeof errorData === "string" && errorData ? errorData : "Request failed";
    if (errorData && typeof errorData === "object") {
      const detail = (errorData as { detail?: unknown }).detail;
      if (typeof detail === "string" && detail) {
        message = detail;
      } else if (Array.isArray(detail) && detail.length) {
        const first = detail[0] as { msg?: unknown };
        if (
          first &&
          typeof first === "object" &&
          typeof first.msg === "string"
        ) {
          message = first.msg;
        }
      }
    }
    throw new ApiError(response.status, message, errorData);
  }

  if (response.status === 204) {
    return {
      data: undefined,
      status: response.status,
      headers: response.headers,
    } as T;
  }

  const contentType = response.headers.get("content-type") ?? "";
  const isJson =
    contentType.includes("application/json") || contentType.includes("+json");
  if (isJson) {
    const data = (await response.json()) as unknown;
    return { data, status: response.status, headers: response.headers } as T;
  }
  if (contentType.includes("text/event-stream")) {
    return {
      data: response,
      status: response.status,
      headers: response.headers,
    } as T;
  }
  const text = await response.text().catch(() => "");
  return {
    data: text,
    status: response.status,
    headers: response.headers,
  } as T;
};
