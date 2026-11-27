/**
 * Backend name of the only supported Git service. Sveltia CMS sends it as the `provider` parameter
 * and expects it in the messages posted by the authorization popup.
 */
const PROVIDER = 'github';
/**
 * Pattern of the cookie that holds the CSRF token during the authorization flow.
 */
const CSRF_COOKIE_PATTERN = new RegExp(`\\bcsrf-token=${PROVIDER}_([0-9a-f]{32})\\b`);

const GITHUB_SCOPES = {
  default: 'repo,user',
  allowed: ['repo', 'public_repo', 'user', 'read:user', 'user:email'],
};

const getScope = (requested, env) => {
  const { default: fallback, allowed } = GITHUB_SCOPES;
  let scopes = (requested ?? '').split(/[\s,]+/).filter(Boolean);
  const allowWorkflow = env.GITHUB_ALLOW_WORKFLOW_SCOPE === 'true';

  if (!allowWorkflow && scopes.includes('workflow')) {
    // eslint-disable-next-line no-console
    console.warn(
      'Ignoring the "workflow" scope. With an OAuth app, set ' +
        'GITHUB_ALLOW_WORKFLOW_SCOPE to "true" to allow it. A GitHub App ignores scopes; grant ' +
        'the Workflows permission instead.',
    );

    scopes = scopes.filter((scope) => scope !== 'workflow');
  }

  if (!scopes.length) {
    return fallback;
  }

  if (scopes.every((scope) => allowed.includes(scope) || (allowWorkflow && scope === 'workflow'))) {
    return scopes.join(',');
  }

  // eslint-disable-next-line no-console
  console.warn(`Ignoring the unsupported "${requested}" scope; requesting "${fallback}".`);

  return fallback;
};

const escapeRegExp = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const getDomainPatterns = (allowedDomains) =>
  (allowedDomains ?? '')
    .split(/,/)
    .map((str) => str.trim())
    .filter(Boolean)
    .map((str) => `^${escapeRegExp(str).replaceAll('\\*', '.+')}$`);

const isAllowedHostname = (hostname, patterns) =>
  patterns.some((pattern) => new RegExp(pattern).test(hostname));

const serialize = (value) => JSON.stringify(value ?? null).replaceAll('<', '\\u003c');

const outputHTML = ({ provider = PROVIDER, token, refreshToken, error, errorCode, env = {} }) => {
  const state = error ? 'error' : 'success';
  const content = error ? { provider, error, errorCode } : { provider, token, refreshToken };
  const handshake = `authorizing:${provider}`;
  const message = `authorization:${provider}:${state}:${JSON.stringify(content)}`;

  return new Response(
    `
      <!doctype html><html><body><script>
        (() => {
          const trustedPatterns = ${serialize(getDomainPatterns(env.ALLOWED_DOMAINS))};
          const hasToken = ${serialize(!!token)};
          const handshake = ${serialize(handshake)};
          const message = ${serialize(message)};

          const isTrusted = (origin) => {
            try {
              const { hostname } = new URL(origin);

              return trustedPatterns.some((pattern) => new RegExp(pattern).test(hostname));
            } catch {
              return false;
            }
          };

          window.addEventListener('message', ({ data, origin }) => {
            if (data !== handshake) {
              return;
            }

            if (hasToken && trustedPatterns.length && !isTrusted(origin)) {
              return;
            }

            window.opener?.postMessage(message, origin);
          });
          window.opener?.postMessage(handshake, '*');
        })();
      </script></body></html>
    `,
    {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'Cache-Control': 'no-store',
        'Set-Cookie': `csrf-token=deleted; HttpOnly; Max-Age=0; Path=/; SameSite=Lax; Secure`,
      },
    },
  );
};

const errorMessages = {
  UNSUPPORTED_BACKEND: 'Your Git backend is not supported by the authenticator.',
  UNSUPPORTED_DOMAIN: 'Your domain is not allowed to use the authenticator.',
  MISCONFIGURED_CLIENT: 'GitHub App client ID or secret is not configured.',
  AUTH_CODE_REQUEST_FAILED: 'Failed to receive an authorization code. Please try again later.',
  CSRF_DETECTED: 'Potential CSRF attack detected. Authentication flow aborted.',
  TOKEN_REQUEST_FAILED: 'Failed to request an access token. Please try again later.',
  MALFORMED_RESPONSE: 'Server responded with malformed data. Please try again later.',
};

const outputError = (errorCode, env, provider) =>
  outputHTML({ env, provider, error: errorMessages[errorCode], errorCode });

const isClientConfigured = ({ GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET }) =>
  !!GITHUB_CLIENT_ID && !!GITHUB_CLIENT_SECRET;

const requestToken = async (params, env) => {
  const { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_HOSTNAME = 'github.com' } = env;

  try {
    return await fetch(`https://${GITHUB_HOSTNAME}/login/oauth/access_token`, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        ...params,
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
      }),
    });
  } catch {
    return undefined;
  }
};

const handleAuth = async (request, env) => {
  const { url } = request;
  const { searchParams } = new URL(url);
  const { provider, site_id: domain, scope: requestedScope } = Object.fromEntries(searchParams);

  if (provider !== PROVIDER) {
    return outputError(
      'UNSUPPORTED_BACKEND',
      env,
      /^[a-z-]+$/.test(provider ?? '') ? provider : 'unknown',
    );
  }

  const scope = getScope(requestedScope, env);
  const { ALLOWED_DOMAINS, GITHUB_CLIENT_ID, GITHUB_HOSTNAME = 'github.com' } = env;
  const domainPatterns = getDomainPatterns(ALLOWED_DOMAINS);

  if (domainPatterns.length && !isAllowedHostname(domain ?? '', domainPatterns)) {
    return outputError('UNSUPPORTED_DOMAIN', env);
  }

  if (!isClientConfigured(env)) {
    return outputError('MISCONFIGURED_CLIENT', env);
  }

  const csrfToken = globalThis.crypto.randomUUID().replaceAll('-', '');

  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    scope,
    state: csrfToken,
  });

  const authURL = `https://${GITHUB_HOSTNAME}/login/oauth/authorize?${params.toString()}`;

  return new Response('', {
    status: 302,
    headers: {
      Location: authURL,
      'Set-Cookie':
        `csrf-token=${PROVIDER}_${csrfToken}; ` +
        `HttpOnly; Path=/; Max-Age=600; SameSite=Lax; Secure`,
    },
  });
};

const handleCallback = async (request, env) => {
  const { url, headers } = request;
  const { searchParams } = new URL(url);
  const { code, state } = Object.fromEntries(searchParams);
  const [, csrfToken] = headers.get('Cookie')?.match(CSRF_COOKIE_PATTERN) ?? [];

  if (!code || !state) {
    return outputError('AUTH_CODE_REQUEST_FAILED', env);
  }

  if (!csrfToken || state !== csrfToken) {
    return outputError('CSRF_DETECTED', env);
  }

  if (!isClientConfigured(env)) {
    return outputError('MISCONFIGURED_CLIENT', env);
  }

  const response = await requestToken({ code }, env);

  if (!response) {
    return outputError('TOKEN_REQUEST_FAILED', env);
  }

  let result;

  try {
    result = await response.json();
  } catch {
    //
  }

  const { access_token: token, refresh_token: refreshToken, error } = result ?? {};

  if (!token && !error) {
    return outputError('MALFORMED_RESPONSE', env);
  }

  return outputHTML({ env, token, refreshToken, error });
};

const getCorsHeaders = (request, env) => {
  const origin = request.headers.get('Origin');

  if (!origin) {
    return undefined;
  }

  const domainPatterns = getDomainPatterns(env.ALLOWED_DOMAINS);
  let hostname = '';

  try {
    ({ hostname } = new URL(origin));
  } catch {
    //
  }

  if (!hostname || (domainPatterns.length && !isAllowedHostname(hostname, domainPatterns))) {
    return undefined;
  }

  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'POST',
    'Access-Control-Allow-Headers': 'Accept, Content-Type',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
};

const outputJSON = (body, { status = 200, headers = {} } = {}) =>
  Response.json(body, { status, headers: { 'Cache-Control': 'no-store', ...headers } });

const handleRefresh = async (request, env) => {
  const corsHeaders = getCorsHeaders(request, env);

  if (!corsHeaders) {
    return outputJSON({ error: 'unsupported_domain' }, { status: 403 });
  }

  let params;

  try {
    params = await request.json();
  } catch {
    //
  }

  const refreshToken = params?.refresh_token;

  if (params?.grant_type !== 'refresh_token' || typeof refreshToken !== 'string' || !refreshToken) {
    return outputJSON({ error: 'invalid_request' }, { status: 400, headers: corsHeaders });
  }

  if (!isClientConfigured(env)) {
    return outputJSON({ error: 'misconfigured_client' }, { status: 500, headers: corsHeaders });
  }

  const response = await requestToken(
    { grant_type: 'refresh_token', refresh_token: refreshToken },
    env,
  );

  let result;

  try {
    result = await response?.json();
  } catch {
    //
  }

  if (!response || !result) {
    return outputJSON({ error: 'token_request_failed' }, { status: 502, headers: corsHeaders });
  }

  return outputJSON(result, { status: response.status, headers: corsHeaders });
};

const handlePreflight = (request, env) =>
  new Response(null, { status: 204, headers: getCorsHeaders(request, env) ?? {} });

export default {
  async fetch(request, env) {
    const { method, url } = request;
    const { pathname } = new URL(url);

    if (method === 'GET' && ['/auth', '/oauth/authorize'].includes(pathname)) {
      return handleAuth(request, env);
    }

    if (method === 'GET' && ['/callback', '/oauth/redirect'].includes(pathname)) {
      return handleCallback(request, env);
    }

    if (['/auth', '/oauth/access_token'].includes(pathname)) {
      if (method === 'OPTIONS') {
        return handlePreflight(request, env);
      }

      if (method === 'POST') {
        return handleRefresh(request, env);
      }
    }

    return new Response('', { status: 404 });
  },
};
