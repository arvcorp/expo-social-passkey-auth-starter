import { Platform } from "react-native";
import * as AppleAuthentication from "expo-apple-authentication";

let PasskeyModule: typeof import("react-native-passkey") | null = null;
if (Platform.OS !== "web") {
  try {
    PasskeyModule = require("react-native-passkey");
  } catch {
    // Native module is unavailable in Expo Go and web builds.
  }
}

export interface AuthenticatedUser {
  id: string;
  email?: string | null;
  name?: string | null;
  avatarUrl?: string | null;
}

export interface AuthResult {
  success: boolean;
  user: AuthenticatedUser;
  isNewUser?: boolean;
}

export type AuthRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

export class AuthApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = "AuthApiError";
  }
}

/**
 * Creates a small request client for an Express session-cookie backend.
 * If your app uses another HTTP client, provide an equivalent AuthRequest that
 * preserves the authentication session on each request.
 */
export function createAuthRequest(apiBaseUrl: string): AuthRequest {
  const base = apiBaseUrl.replace(/\/+$/, "");

  return async <T>(path: string, init: RequestInit = {}) => {
    const response = await fetch(`${base}${path.startsWith("/") ? path : `/${path}`}`, {
      ...init,
      credentials: "include",
      headers: {
        Accept: "application/json",
        ...(init.body ? { "Content-Type": "application/json" } : {}),
        ...init.headers,
      },
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new AuthApiError(data.error || "Authentication request failed", response.status);
    }
    return data as T;
  };
}

export async function signInWithApple(request: AuthRequest): Promise<AuthResult> {
  if (Platform.OS !== "ios") {
    throw new Error("Apple Sign In is available only on iOS.");
  }

  const credential = await AppleAuthentication.signInAsync({
    requestedScopes: [
      AppleAuthentication.AppleAuthenticationScope.FULL_NAME,
      AppleAuthentication.AppleAuthenticationScope.EMAIL,
    ],
  });
  if (!credential.identityToken) {
    throw new Error("Apple did not return an identity token.");
  }

  return request<AuthResult>("/api/auth/apple", {
    method: "POST",
    body: JSON.stringify({
      identityToken: credential.identityToken,
      fullName: credential.fullName,
    }),
  });
}

function getPasskey() {
  if (!PasskeyModule || Platform.OS === "web") {
    throw new Error("Passkeys require a native development, preview, or production build.");
  }
  if (!PasskeyModule.Passkey.isSupported()) {
    throw new Error("Passkeys are not supported on this device.");
  }
  return PasskeyModule.Passkey;
}

export async function signInWithPasskey(request: AuthRequest): Promise<AuthResult> {
  const passkey = getPasskey();
  const options = await request<Record<string, unknown>>("/api/auth/passkey/auth-options");
  const response = await passkey.get(options as any);
  return request<AuthResult>("/api/auth/passkey/auth-verify", {
    method: "POST",
    body: JSON.stringify(response),
  });
}

export async function registerPasskey(request: AuthRequest): Promise<void> {
  const passkey = getPasskey();
  const options = await request<Record<string, unknown>>("/api/auth/passkey/register-options");
  const response = await passkey.create(options as any);
  const result = await request<{ verified: boolean; error?: string }>("/api/auth/passkey/register-verify", {
    method: "POST",
    body: JSON.stringify(response),
  });
  if (!result.verified) {
    throw new Error(result.error || "Passkey registration could not be verified.");
  }
}

export interface PasskeyCredential {
  id: string;
  createdAt: string;
  deviceType: string;
}

export function listPasskeys(request: AuthRequest) {
  return request<{ credentials: PasskeyCredential[] }>("/api/auth/passkey/credentials");
}

export async function removePasskey(request: AuthRequest, credentialId: string): Promise<void> {
  await request<{ success: boolean }>(`/api/auth/passkey/credentials/${encodeURIComponent(credentialId)}`, {
    method: "DELETE",
  });
}