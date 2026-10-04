const TOKEN_KEY = "selkie_jwt";

export interface JWTClaims {
  sub: string;
  is_super?: boolean;
  exp?: number;
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  const claims = parseJWT(token);
  if (!claims || ["email", "display_name", "picture"].some((key) => key in claims)) {
    throw new Error("A reference-only session is required before saving.");
  }
  localStorage.setItem(TOKEN_KEY, token);
}

export function removeToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

export function parseJWT(token: string): JWTClaims | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    return JSON.parse(
      atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")),
    );
  } catch {
    return null;
  }
}

export function isTokenValid(token: string): boolean {
  const claims = parseJWT(token);
  if (!claims) return false;
  if (claims.exp && claims.exp * 1000 < Date.now()) return false;
  return true;
}

export function extractTokenFromHash(): string | null {
  const hash = window.location.hash;
  if (hash.startsWith("#token=")) {
    const token = hash.substring(7);
    if (token) {
      window.history.replaceState(null, "", window.location.pathname);
      return token;
    }
  }
  return null;
}
