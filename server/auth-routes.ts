import { Router, type Request, type Response } from "express";
import type { Pool } from "pg";
import { OAuth2Client } from "google-auth-library";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";

export type AuthProvider = "google" | "apple";

export interface AuthenticatedUser {
  id: string;
  email?: string | null;
  name?: string | null;
  avatarUrl?: string | null;
}

export interface AuthUserStore {
  findByProvider(provider: AuthProvider, providerId: string): Promise<AuthenticatedUser | null>;
  findByEmail(email: string): Promise<AuthenticatedUser | null>;
  createSocialUser(
    provider: AuthProvider,
    providerId: string,
    profile: { email?: string; name?: string; avatarUrl?: string },
  ): Promise<AuthenticatedUser>;
  findById(userId: string): Promise<AuthenticatedUser | null>;
}

export interface AuthStarterConfig {
  googleClientIds: string[];
  appleClientId: string;
  passkeyRpId: string;
  passkeyRpName: string;
  passkeyOrigins: string[];
  appleAppId: string;
  androidPackageName: string;
  androidCertificateFingerprints: string[];
}

interface PasskeyCredentialRow {
  id: string;
  user_id: string;
  credential_id: string;
  public_key: string;
  counter: number;
  device_type: string;
  transports: string | null;
  created_at: string;
}

function requireConfig(config: AuthStarterConfig) {
  const missing: string[] = [];
  if (!config.googleClientIds.filter(Boolean).length) missing.push("googleClientIds");
  if (!config.appleClientId) missing.push("appleClientId");
  if (!config.passkeyRpId) missing.push("passkeyRpId");
  if (!config.passkeyRpName) missing.push("passkeyRpName");
  if (!config.passkeyOrigins.filter(Boolean).length) missing.push("passkeyOrigins");
  if (!config.appleAppId) missing.push("appleAppId");
  if (!config.androidPackageName) missing.push("androidPackageName");
  if (!config.androidCertificateFingerprints.filter(Boolean).length) {
    missing.push("androidCertificateFingerprints");
  }
  if (missing.length) {
    throw new Error(`Auth starter is missing required configuration: ${missing.join(", ")}`);
  }
}

function sanitizeUser(user: AuthenticatedUser) {
  return {
    id: user.id,
    email: user.email ?? null,
    name: user.name ?? null,
    avatarUrl: user.avatarUrl ?? null,
  };
}

async function createSession(req: Request, userId: string) {
  await new Promise<void>((resolve, reject) => {
    req.session.regenerate((error) => (error ? reject(error) : resolve()));
  });
  (req.session as any).userId = userId;
  await new Promise<void>((resolve, reject) => {
    req.session.save((error) => (error ? reject(error) : resolve()));
  });
}

async function destroySession(req: Request) {
  await new Promise<void>((resolve, reject) => {
    req.session.destroy((error) => (error ? reject(error) : resolve()));
  });
}

function sessionUserId(req: Request) {
  return (req.session as any).userId as string | undefined;
}

async function sendSocialLogin(
  req: Request,
  res: Response,
  store: AuthUserStore,
  provider: AuthProvider,
  providerId: string,
  profile: { email?: string; name?: string; avatarUrl?: string },
) {
  let user = await store.findByProvider(provider, providerId);
  let isNewUser = false;

  // Never silently link a provider to an account that merely has the same
  // email. That permits account takeover when an app has stale/recycled or
  // historically unverified addresses. Implement provider linking separately
  // behind an existing authenticated session and explicit user confirmation.
  if (!user && profile.email) {
    const existingUser = await store.findByEmail(profile.email.toLowerCase());
    if (existingUser) {
      res.status(409).json({
        error: "An account already uses this email. Sign in with your existing method, then link this provider in account settings.",
      });
      return;
    }
  }

  if (!user) {
    user = await store.createSocialUser(provider, providerId, profile);
    isNewUser = true;
  }

  await createSession(req, user.id);
  res.json({ success: true, user: sanitizeUser(user), isNewUser });
}

export function createAuthRouter({
  pool,
  userStore,
  config,
}: {
  pool: Pool;
  userStore: AuthUserStore;
  config: AuthStarterConfig;
}) {
  requireConfig(config);
  const router = Router();
  const googleClient = new OAuth2Client();

  router.get("/session", async (req, res) => {
    const userId = sessionUserId(req);
    if (!userId) {
      res.json({ authenticated: false });
      return;
    }
    const user = await userStore.findById(userId);
    if (!user) {
      await destroySession(req).catch(() => {});
      res.json({ authenticated: false });
      return;
    }
    res.json({ authenticated: true, user: sanitizeUser(user) });
  });

  router.post("/logout", async (req, res) => {
    await destroySession(req).catch(() => {});
    res.clearCookie("connect.sid");
    res.json({ success: true });
  });

  router.post("/google", async (req, res) => {
    try {
      const idToken = String(req.body?.idToken || "");
      if (!idToken) {
        res.status(400).json({ error: "Missing Google ID token." });
        return;
      }

      const ticket = await googleClient.verifyIdToken({
        idToken,
        audience: config.googleClientIds.filter(Boolean),
      });
      const payload = ticket.getPayload();
      if (!payload?.sub) {
        res.status(401).json({ error: "Google token could not be verified." });
        return;
      }
      if (!payload.email || payload.email_verified !== true) {
        res.status(401).json({ error: "Google did not provide a verified email address." });
        return;
      }

      await sendSocialLogin(req, res, userStore, "google", payload.sub, {
        email: payload.email?.toLowerCase(),
        name: payload.name,
        avatarUrl: payload.picture,
      });
    } catch {
      res.status(401).json({ error: "Google Sign-In failed. Please try again." });
    }
  });

  router.post("/apple", async (req, res) => {
    try {
      const identityToken = String(req.body?.identityToken || "");
      if (!identityToken) {
        res.status(400).json({ error: "Missing Apple identity token." });
        return;
      }

      const appleSignin = await import("apple-signin-auth");
      const verifyIdToken = (appleSignin as any).verifyIdToken || (appleSignin as any).default?.verifyIdToken;
      const payload = await verifyIdToken(identityToken, {
        audience: config.appleClientId,
        ignoreExpiration: false,
      });
      if (!payload?.sub) {
        res.status(401).json({ error: "Apple token could not be verified." });
        return;
      }
      // Apple commonly supplies name/email only on first consent. A known Apple
      // subject remains safe to sign in with even when those optional claims no
      // longer appear in subsequent identity tokens.
      const existingAppleUser = await userStore.findByProvider("apple", payload.sub);
      if (existingAppleUser) {
        await createSession(req, existingAppleUser.id);
        res.json({ success: true, user: sanitizeUser(existingAppleUser), isNewUser: false });
        return;
      }
      if (!payload.email || (payload.email_verified !== true && payload.email_verified !== "true")) {
        res.status(401).json({ error: "Apple did not provide a verified email address." });
        return;
      }

      const fullName = req.body?.fullName;
      const name = fullName
        ? [fullName.givenName, fullName.familyName].filter(Boolean).join(" ")
        : undefined;
      await sendSocialLogin(req, res, userStore, "apple", payload.sub, {
        email: payload.email?.toLowerCase(),
        name,
      });
    } catch {
      res.status(401).json({ error: "Apple Sign-In failed. Please try again." });
    }
  });

  router.get("/passkey/available", (_req, res) => {
    res.json({ available: true });
  });

  router.get("/passkey/register-options", async (req, res) => {
    const userId = sessionUserId(req);
    if (!userId) {
      res.status(401).json({ error: "Sign in before adding a passkey." });
      return;
    }
    const user = await userStore.findById(userId);
    if (!user) {
      res.status(401).json({ error: "User not found." });
      return;
    }

    try {
      const existing = await pool.query<Pick<PasskeyCredentialRow, "credential_id" | "transports">>(
        "SELECT credential_id, transports FROM passkey_credentials WHERE user_id = $1",
        [user.id],
      );
      const options = await generateRegistrationOptions({
        rpName: config.passkeyRpName,
        rpID: config.passkeyRpId,
        userName: user.email || user.name || user.id,
        userID: Buffer.from(user.id),
        attestationType: "none",
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          residentKey: "preferred",
          userVerification: "preferred",
        },
        excludeCredentials: existing.rows.map((credential) => ({
          id: credential.credential_id,
          transports: credential.transports ? JSON.parse(credential.transports) : undefined,
        })),
      });
      (req.session as any).passkeyRegistrationChallenge = options.challenge;
      await new Promise<void>((resolve, reject) => {
        req.session.save((error) => (error ? reject(error) : resolve()));
      });
      res.json(options);
    } catch {
      res.status(500).json({ error: "Could not start passkey registration." });
    }
  });

  router.post("/passkey/register-verify", async (req, res) => {
    const userId = sessionUserId(req);
    const expectedChallenge = (req.session as any).passkeyRegistrationChallenge;
    if (!userId || !expectedChallenge) {
      res.status(400).json({ error: "Start passkey registration again." });
      return;
    }

    try {
      const verification = await verifyRegistrationResponse({
        response: req.body,
        expectedChallenge,
        expectedOrigin: config.passkeyOrigins,
        expectedRPID: config.passkeyRpId,
        requireUserVerification: true,
      });
      if (!verification.verified || !verification.registrationInfo) {
        res.status(400).json({ error: "Passkey registration was not verified." });
        return;
      }

      const credential = verification.registrationInfo.credential;
      await pool.query(
        `INSERT INTO passkey_credentials (user_id, credential_id, public_key, counter, device_type, transports)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (credential_id) DO UPDATE
           SET counter = EXCLUDED.counter, device_type = EXCLUDED.device_type, transports = EXCLUDED.transports`,
        [
          userId,
          credential.id,
          Buffer.from(credential.publicKey).toString("base64url"),
          credential.counter,
          verification.registrationInfo.credentialDeviceType || "singleDevice",
          credential.transports ? JSON.stringify(credential.transports) : null,
        ],
      );
      delete (req.session as any).passkeyRegistrationChallenge;
      res.json({ verified: true });
    } catch {
      res.status(400).json({ error: "Passkey registration could not be verified." });
    }
  });

  router.get("/passkey/auth-options", async (req, res) => {
    try {
      const options = await generateAuthenticationOptions({
        rpID: config.passkeyRpId,
        userVerification: "preferred",
      });
      (req.session as any).passkeyAuthenticationChallenge = options.challenge;
      await new Promise<void>((resolve, reject) => {
        req.session.save((error) => (error ? reject(error) : resolve()));
      });
      res.json(options);
    } catch {
      res.status(500).json({ error: "Could not start passkey sign-in." });
    }
  });

  router.post("/passkey/auth-verify", async (req, res) => {
    const expectedChallenge = (req.session as any).passkeyAuthenticationChallenge;
    const credentialId = String(req.body?.id || "");
    if (!expectedChallenge || !credentialId) {
      res.status(400).json({ error: "Start passkey sign-in again." });
      return;
    }

    try {
      const credentialResult = await pool.query<PasskeyCredentialRow>(
        "SELECT * FROM passkey_credentials WHERE credential_id = $1",
        [credentialId],
      );
      const storedCredential = credentialResult.rows[0];
      if (!storedCredential) {
        res.status(401).json({ error: "Passkey not found." });
        return;
      }

      const verification = await verifyAuthenticationResponse({
        response: req.body,
        expectedChallenge,
        expectedOrigin: config.passkeyOrigins,
        expectedRPID: config.passkeyRpId,
        credential: {
          id: storedCredential.credential_id,
          publicKey: Buffer.from(storedCredential.public_key, "base64url"),
          counter: storedCredential.counter,
          transports: storedCredential.transports ? JSON.parse(storedCredential.transports) : undefined,
        },
        requireUserVerification: true,
      });
      if (!verification.verified) {
        res.status(401).json({ error: "Passkey sign-in was not verified." });
        return;
      }

      await pool.query(
        "UPDATE passkey_credentials SET counter = $1 WHERE credential_id = $2",
        [verification.authenticationInfo.newCounter, storedCredential.credential_id],
      );
      const user = await userStore.findById(storedCredential.user_id);
      if (!user) {
        res.status(401).json({ error: "User not found." });
        return;
      }

      await createSession(req, user.id);
      delete (req.session as any).passkeyAuthenticationChallenge;
      res.json({ success: true, user: sanitizeUser(user), isNewUser: false });
    } catch {
      res.status(401).json({ error: "Passkey sign-in failed." });
    }
  });

  router.get("/passkey/credentials", async (req, res) => {
    const userId = sessionUserId(req);
    if (!userId) {
      res.status(401).json({ error: "Not authenticated." });
      return;
    }
    const credentials = await pool.query<Pick<PasskeyCredentialRow, "id" | "created_at" | "device_type">>(
      "SELECT id, created_at, device_type FROM passkey_credentials WHERE user_id = $1 ORDER BY created_at DESC",
      [userId],
    );
    res.json({
      credentials: credentials.rows.map((credential) => ({
        id: credential.id,
        createdAt: credential.created_at,
        deviceType: credential.device_type,
      })),
    });
  });

  router.delete("/passkey/credentials/:credentialId", async (req, res) => {
    const userId = sessionUserId(req);
    if (!userId) {
      res.status(401).json({ error: "Not authenticated." });
      return;
    }
    await pool.query(
      "DELETE FROM passkey_credentials WHERE id = $1 AND user_id = $2",
      [req.params.credentialId, userId],
    );
    res.json({ success: true });
  });

  return router;
}

/**
 * Mount at the Express app root, not below /api:
 * app.use(createPasskeyAssociationRouter(config));
 */
export function createPasskeyAssociationRouter(config: AuthStarterConfig) {
  requireConfig(config);
  const router = Router();

  router.get("/.well-known/apple-app-site-association", (_req, res) => {
    res.type("application/json").json({
      webcredentials: { apps: [config.appleAppId] },
    });
  });

  router.get("/.well-known/assetlinks.json", (_req, res) => {
    res.type("application/json").json([
      {
        relation: [
          "delegate_permission/common.handle_all_urls",
          "delegate_permission/common.get_login_creds",
        ],
        target: {
          namespace: "android_app",
          package_name: config.androidPackageName,
          sha256_cert_fingerprints: config.androidCertificateFingerprints,
        },
      },
    ]);
  });

  return router;
}