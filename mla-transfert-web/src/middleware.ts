import { defineMiddleware } from 'astro:middleware';

export const onRequest = defineMiddleware((_ctx, next) => {
  return next().then((response) => {
    // Ne pas écraser si déjà défini (ex. par un reverse proxy)
    if (!response.headers.has('Content-Security-Policy')) {
      response.headers.set(
        'Content-Security-Policy',
        [
          "default-src 'self'",
          // unsafe-inline requis : Astro génère des scripts inline pour l'hydration React
          // wasm-unsafe-eval requis pour MLA WASM
          "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https://static.cloudflareinsights.com",
          "style-src 'self' 'unsafe-inline'",
          "img-src 'self' data:",
          "connect-src 'self' wss: https://cloudflareinsights.com",
          "font-src 'self' data:",
          "object-src 'none'",
          "frame-ancestors 'none'",
          "base-uri 'self'",
          "form-action 'self'",
        ].join('; '),
      );
    }
    if (!response.headers.has('X-Frame-Options'))
      response.headers.set('X-Frame-Options', 'DENY');
    if (!response.headers.has('X-Content-Type-Options'))
      response.headers.set('X-Content-Type-Options', 'nosniff');
    if (!response.headers.has('Referrer-Policy'))
      response.headers.set('Referrer-Policy', 'no-referrer');
    // HSTS uniquement en HTTPS — ne pas forcer en dev
    if (
      _ctx.url.protocol === 'https:' &&
      !response.headers.has('Strict-Transport-Security')
    ) {
      response.headers.set(
        'Strict-Transport-Security',
        'max-age=31536000; includeSubDomains',
      );
    }
    return response;
  });
});
