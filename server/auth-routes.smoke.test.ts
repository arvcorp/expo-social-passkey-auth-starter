import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";
import express from "express";
import session from "express-session";
import type { AddressInfo } from "node:net";
import {
  createAuthRouter,
  type AuthStarterConfig,
  type AuthUserStore,
} from "./auth-routes";

const config: AuthStarterConfig = {
  googleClientIds: ["smoke-test.apps.googleusercontent.com"],
  appleClientId: "com.example.smoketest",
  passkeyRpId: "auth.example.com",
  passkeyRpName: "Smoke Test",
  passkeyOrigins: ["https://auth.example.com"],
  appleAppId: "TEAMID.com.example.smoketest",
  androidPackageName: "com.example.smoketest",
  androidCertificateFingerprints: ["AA:BB:CC"],
};

const userStore: AuthUserStore = {
  findByProvider: async () => null,
  findByEmail: async () => null,
  createSocialUser: async () => {
    throw new Error("Not reached by malformed-token smoke test");
  },
  findById: async () => null,
};

async function startTestServer() {
  const app = express();
  app.use(
    session({
      secret: "smoke-test-secret",
      resave: false,
      saveUninitialized: true,
    }),
  );
  // The pool is not reached because each test uses intentionally invalid input.
  app.use("/api/auth", createAuthRouter({ pool: {} as any, userStore, config }));
  const server = app.listen(0);
  await once(server, "listening");
  const { port } = server.address() as AddressInfo;
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

async function postJson(baseUrl: string, path: string, body: object) {
  return fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

test("all authentication POST routes receive JSON request bodies", async () => {
  const { server, baseUrl } = await startTestServer();
  try {
    // 401, instead of "Missing ... token" (400), proves the router received
    // the JSON token fields before provider verification was attempted.
    assert.equal((await postJson(baseUrl, "/api/auth/google", { idToken: "not-a-google-token" })).status, 401);
    assert.equal((await postJson(baseUrl, "/api/auth/apple", { identityToken: "not-an-apple-token" })).status, 401);

    // These verify routes accept a JSON object and safely reject an incomplete
    // request before any database work is attempted.
    assert.equal((await postJson(baseUrl, "/api/auth/passkey/register-verify", { id: "credential" })).status, 400);
    assert.equal((await postJson(baseUrl, "/api/auth/passkey/auth-verify", { id: "credential" })).status, 400);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
});