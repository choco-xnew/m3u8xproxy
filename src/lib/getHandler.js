import { isValidHostName } from "./isValidHostName.js";
import { getProxyForUrl } from "proxy-from-env";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "url";
import { dirname } from "path";
import withCORS from "./withCORS.js";
import parseURL from "./parseURL.js";
import proxyM3U8 from "./proxyM3U8.js";
import { proxyTs } from "./proxyTS.js";

export default function getHandler(options, proxy) {
  const corsAnywhere = {
    handleInitialRequest: null,
    getProxyForUrl: getProxyForUrl,
    maxRedirects: 5,
    originBlacklist: [],
    originWhitelist: [],
    checkRateLimit: null,
    redirectSameOrigin: false,
    requireHeader: null,
    removeHeaders: [],
    setHeaders: {},
    corsMaxAge: 0,
  };

  Object.keys(corsAnywhere).forEach(function (option) {
    if (Object.prototype.hasOwnProperty.call(options, option)) {
      corsAnywhere[option] = options[option];
    }
  });

  if (corsAnywhere.requireHeader) {
    if (typeof corsAnywhere.requireHeader === "string") {
      corsAnywhere.requireHeader = [corsAnywhere.requireHeader.toLowerCase()];
    } else if (
      !Array.isArray(corsAnywhere.requireHeader) ||
      corsAnywhere.requireHeader.length === 0
    ) {
      corsAnywhere.requireHeader = null;
    } else {
      corsAnywhere.requireHeader = corsAnywhere.requireHeader.map(h =>
        h.toLowerCase()
      );
    }
  }

  const hasRequiredHeaders = function (headers) {
    return (
      !corsAnywhere.requireHeader ||
      corsAnywhere.requireHeader.some(h =>
        Object.hasOwnProperty.call(headers, h)
      )
    );
  };

  return function (req, res) {
    req.corsAnywhereRequestState = {
      getProxyForUrl: corsAnywhere.getProxyForUrl,
      maxRedirects: corsAnywhere.maxRedirects,
      corsMaxAge: corsAnywhere.corsMaxAge,
    };

    const cors_headers = withCORS({}, req);

    // OPTIONS preflight
    if (req.method === "OPTIONS") {
      res.writeHead(200, cors_headers);
      res.end();
      return;
    }

    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);

    /* =====================================================
       🔓 FREE ACCESS ZONE (NO CORS / NO ORIGIN CHECK)
       ===================================================== */
    if (req.url === "/" || req.url === "/index.html") {
      res.writeHead(200, {
        "Content-Type": "text/html",
        "Access-Control-Allow-Origin": "*",
      });
      res.end(readFileSync(join(__dirname, "../index.html")));
      return;
    }

    const location = parseURL(req.url.slice(1));

    if (
      corsAnywhere.handleInitialRequest &&
      corsAnywhere.handleInitialRequest(req, res, location)
    ) {
      return;
    }

    if (!location) {
      if (/^\/https?:\/[^/]/i.test(req.url)) {
        res.writeHead(400, "Missing slash", cors_headers);
        res.end(
          "The URL is invalid: two slashes are needed after the http(s):."
        );
        return;
      }

      res.end(readFileSync(join(__dirname, "../index.html")));
      return;
    }

    if (location.host === "iscorsneeded") {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("no");
      return;
    }

    if ((Number(location.port) ?? 0) > 65535) {
      res.writeHead(400, "Invalid port", cors_headers);
      res.end("Port number too large: " + location.port);
      return;
    }

    if (!/^\/https?:/.test(req.url) && !isValidHostName(location.hostname)) {
      const uri = new URL(req.url, "http://localhost");

      if (uri.pathname === "/m3u8-proxy") {
        let headers = {};
        try {
          headers = JSON.parse(uri.searchParams.get("headers") ?? "{}");
        } catch (e) {
          res.writeHead(500);
          res.end(e.message);
          return;
        }
        return proxyM3U8(uri.searchParams.get("url") ?? "", headers, res);
      }

      if (uri.pathname === "/ts-proxy") {
        let headers = {};
        try {
          headers = JSON.parse(uri.searchParams.get("headers") ?? "{}");
        } catch (e) {
          res.writeHead(500);
          res.end(e.message);
          return;
        }
        return proxyTs(
          uri.searchParams.get("url") ?? "",
          headers,
          req,
          res
        );
      }

      res.writeHead(404, "Invalid host", cors_headers);
      res.end("Invalid host: " + location.hostname);
      return;
    }

    /* =====================
       🔒 CORS SECURITY ZONE
       ===================== */

    if (!hasRequiredHeaders(req.headers)) {
      res.writeHead(400, "Header required", cors_headers);
      res.end(
        "Missing required request header. Must specify one of: " +
          corsAnywhere.requireHeader
      );
      return;
    }

    const origin = req.headers.origin || "";

    if (corsAnywhere.originBlacklist.includes(origin)) {
      res.writeHead(403, "Forbidden", cors_headers);
      res.end(`The origin "${origin}" was blacklisted.`);
      return;
    }

    if (
      corsAnywhere.originWhitelist.length &&
      !corsAnywhere.originWhitelist.includes(origin)
    ) {
      res.writeHead(403, "Forbidden", cors_headers);
      res.end(`The origin "${origin}" was not whitelisted.`);
      return;
    }

    const rateLimitMessage =
      corsAnywhere.checkRateLimit && corsAnywhere.checkRateLimit(origin);
    if (rateLimitMessage) {
      res.writeHead(429, "Too Many Requests", cors_headers);
      res.end(rateLimitMessage);
      return;
    }

    const isRequestedOverHttps =
      req.connection.encrypted ||
      /^\s*https/.test(req.headers["x-forwarded-proto"]);

    const proxyBaseUrl =
      (isRequestedOverHttps ? "https://" : "http://") + req.headers.host;

    corsAnywhere.removeHeaders.forEach(h => delete req.headers[h]);

    Object.keys(corsAnywhere.setHeaders).forEach(h => {
      req.headers[h] = corsAnywhere.setHeaders[h];
    });

    req.corsAnywhereRequestState.location = location;
    req.corsAnywhereRequestState.proxyBaseUrl = proxyBaseUrl;

    proxyRequest(req, res, proxy);
  };
}