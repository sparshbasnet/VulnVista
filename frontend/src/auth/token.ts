/** Single home for the access token so the API client and the auth context agree. */
const TOKEN_KEY = "vulnvista_access_token";

// sessionStorage, not localStorage: the token dies with the tab rather than
// outliving the operator's session on a shared lab machine.
export function readToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function storeToken(token: string): void {
  sessionStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  sessionStorage.removeItem(TOKEN_KEY);
}

/** Fired when the server rejects a token, so the app can drop back to the login screen. */
export const UNAUTHORIZED_EVENT = "vulnvista:unauthorized";
