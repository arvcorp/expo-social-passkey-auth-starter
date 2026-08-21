import { useCallback, useEffect, useState } from "react";
import { Platform } from "react-native";
import * as Google from "expo-auth-session/providers/google";
import * as WebBrowser from "expo-web-browser";
import type { AuthRequest, AuthResult } from "./auth-client";

let NativeGoogleSignIn: typeof import("@react-native-google-signin/google-signin") | null = null;
if (Platform.OS === "android") {
  try {
    NativeGoogleSignIn = require("@react-native-google-signin/google-signin");
  } catch {
    // Expo Go does not contain this native module.
  }
}

WebBrowser.maybeCompleteAuthSession();

export interface GoogleClientIds {
  webClientId: string;
  iosClientId?: string;
  androidClientId?: string;
}

interface UseGoogleSignInOptions {
  clientIds: GoogleClientIds;
  request: AuthRequest;
  onAuthenticated: (result: AuthResult) => Promise<void> | void;
  onError?: (error: Error) => void;
}

/**
 * Use in a login screen:
 * const { signInWithGoogle, loading, ready } = useGoogleSignIn({ ... });
 */
export function useGoogleSignIn({
  clientIds,
  request: apiRequest,
  onAuthenticated,
  onError,
}: UseGoogleSignInOptions) {
  const [loading, setLoading] = useState(false);
  const [googleRequest, googleResponse, promptAsync] = Google.useIdTokenAuthRequest({
    webClientId: clientIds.webClientId,
    iosClientId: clientIds.iosClientId,
    androidClientId: clientIds.androidClientId,
  });

  useEffect(() => {
    if (Platform.OS === "android" && NativeGoogleSignIn) {
      NativeGoogleSignIn.GoogleSignin.configure({
        webClientId: clientIds.webClientId,
      });
    }
  }, [clientIds.webClientId]);

  useEffect(() => {
    if (googleResponse?.type === "dismiss" || googleResponse?.type === "cancel") {
      setLoading(false);
      return;
    }
    if (googleResponse?.type === "error") {
      setLoading(false);
      onError?.(new Error("Google Sign-In was not completed."));
      return;
    }
    if (googleResponse?.type !== "success") return;

    const idToken = googleResponse.authentication?.idToken || (googleResponse.params?.id_token as string | undefined);
    if (!idToken) {
      setLoading(false);
      onError?.(new Error("Google did not return an ID token."));
      return;
    }

    void (async () => {
      try {
        const result = await apiRequest<AuthResult>("/api/auth/google", {
          method: "POST",
          body: JSON.stringify({ idToken }),
        });
        await onAuthenticated(result);
      } catch (error) {
        onError?.(error instanceof Error ? error : new Error("Google Sign-In failed."));
      } finally {
        setLoading(false);
      }
    })();
  }, [apiRequest, googleResponse, onAuthenticated, onError]);

  const signInWithGoogle = useCallback(async () => {
    setLoading(true);
    try {
      if (Platform.OS === "android" && NativeGoogleSignIn) {
        await NativeGoogleSignIn.GoogleSignin.hasPlayServices({
          showPlayServicesUpdateDialog: true,
        });
        await NativeGoogleSignIn.GoogleSignin.signOut().catch(() => {});
        const account = await NativeGoogleSignIn.GoogleSignin.signIn();
        const idToken = account.data?.idToken;
        if (!idToken) throw new Error("Google did not return an ID token.");

        const result = await apiRequest<AuthResult>("/api/auth/google", {
          method: "POST",
          body: JSON.stringify({ idToken }),
        });
        await onAuthenticated(result);
        setLoading(false);
        return;
      }

      if (!googleRequest) {
        throw new Error("Google Sign-In is not ready yet.");
      }
      await promptAsync();
      // iOS/web result is handled by the effect above.
    } catch (error) {
      setLoading(false);
      onError?.(error instanceof Error ? error : new Error("Google Sign-In failed."));
    }
  }, [apiRequest, googleRequest, onAuthenticated, onError, promptAsync]);

  return {
    signInWithGoogle,
    loading,
    ready: Platform.OS === "android" ? NativeGoogleSignIn !== null : googleRequest !== null,
  };
}