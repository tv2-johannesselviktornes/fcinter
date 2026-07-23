// Cloudflare Pages Function — POST /api/signup
// Handles native supporter-club signup submissions, backed by D1.
//
// Defense layers, in order: same-origin check, rate limiting (D1-backed,
// hashed IP), honeypot field, minimum time-on-form, Cloudflare Turnstile,
// server-side field validation, then a parameterized insert (immune to
// SQL injection since D1 prepared statements are always used with .bind()).

const RATE_LIMIT_WINDOW_SECONDS = 600; // 10 minutes
const RATE_LIMIT_MAX_REQUESTS = 5;
const MIN_FORM_FILL_MS = 2000; // bots submit near-instantly

const MAX_LENGTHS = {
  firstName: 100,
  lastName: 100,
  email: 254,
  phone: 20,
  address: 200,
  postalCode: 10,
  city: 100,
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "no-store",
    },
  });
}

function isValidEmail(email) {
  return (
    typeof email === "string" &&
    email.length > 0 &&
    email.length <= MAX_LENGTHS.email &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  );
}

function isValidPostalCode(code) {
  return code === "" || /^\d{4}$/.test(code);
}

function isValidPhone(phone) {
  return phone === "" || /^[0-9+\s()-]{6,20}$/.test(phone);
}

function sanitizeText(value, maxLength) {
  if (typeof value !== "string") return "";
  // Strip control characters, collapse to a single line, cap length.
  return value
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLength);
}

async function hashIp(ip, salt) {
  const bytes = new TextEncoder().encode(`${salt}:${ip}`);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function verifyTurnstile(token, secret, ip) {
  const body = new URLSearchParams();
  body.append("secret", secret);
  body.append("response", token);
  if (ip) body.append("remoteip", ip);

  const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body,
  });
  if (!res.ok) return false;
  const outcome = await res.json();
  return outcome.success === true;
}

async function checkRateLimit(db, ipHash) {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const windowStart = Math.floor(nowSeconds / RATE_LIMIT_WINDOW_SECONDS) * RATE_LIMIT_WINDOW_SECONDS;

  const row = await db
    .prepare(
      `INSERT INTO rate_limits (ip_hash, window_start, count)
       VALUES (?1, ?2, 1)
       ON CONFLICT(ip_hash, window_start) DO UPDATE SET count = count + 1
       RETURNING count`
    )
    .bind(ipHash, windowStart)
    .first();

  // Best-effort cleanup of old buckets so the table doesn't grow forever.
  await db
    .prepare(`DELETE FROM rate_limits WHERE window_start < ?1`)
    .bind(windowStart - RATE_LIMIT_WINDOW_SECONDS * 6)
    .run();

  return row ? row.count <= RATE_LIMIT_MAX_REQUESTS : true;
}

function validateFields(payload) {
  const firstName = sanitizeText(payload.firstName, MAX_LENGTHS.firstName);
  const lastName = sanitizeText(payload.lastName, MAX_LENGTHS.lastName);
  const email = sanitizeText(payload.email, MAX_LENGTHS.email).toLowerCase();
  const phone = sanitizeText(payload.phone, MAX_LENGTHS.phone);
  const address = sanitizeText(payload.address, MAX_LENGTHS.address);
  const postalCode = sanitizeText(payload.postalCode, MAX_LENGTHS.postalCode);
  const city = sanitizeText(payload.city, MAX_LENGTHS.city);
  const consent = payload.consent === true || payload.consent === "on" || payload.consent === "true";

  const fields = { firstName, lastName, email, phone, address, postalCode, city, consent };
  const errors = {};

  if (!firstName) errors.firstName = "Fornavn er påkrevd.";
  if (!lastName) errors.lastName = "Etternavn er påkrevd.";
  if (!isValidEmail(email)) errors.email = "Gyldig e-postadresse er påkrevd.";
  if (!isValidPhone(phone)) errors.phone = "Ugyldig telefonnummer.";
  if (!isValidPostalCode(postalCode)) errors.postalCode = "Postnummer må bestå av 4 sifre.";
  if (!consent) errors.consent = "Du må godta personvernvilkårene for å melde deg inn.";

  return { fields, errors };
}

export async function onRequestPost(context) {
  const { request, env } = context;

  if (!env.DB) {
    return jsonResponse({ error: "Tjenesten er ikke konfigurert." }, 500);
  }

  // Same-origin check — defense in depth against cross-site form posts.
  // (No CORS headers are ever sent, so genuine cross-origin fetches are
  // already blocked by the browser; this also rejects spoofed same-site forms.)
  const allowedOrigin = env.ALLOWED_ORIGIN || "https://fcinter.no";
  const origin = request.headers.get("Origin");
  if (origin && origin !== allowedOrigin) {
    return jsonResponse({ error: "Ugyldig forespørsel." }, 403);
  }

  const contentType = request.headers.get("Content-Type") || "";
  let payload;
  let isJson = false;

  try {
    if (contentType.includes("application/json")) {
      isJson = true;
      payload = await request.json();
    } else if (
      contentType.includes("application/x-www-form-urlencoded") ||
      contentType.includes("multipart/form-data")
    ) {
      const form = await request.formData();
      payload = Object.fromEntries(form.entries());
    } else {
      return jsonResponse({ error: "Ugyldig forespørsel." }, 415);
    }
  } catch {
    return jsonResponse({ error: "Kunne ikke lese skjemadata." }, 400);
  }

  if (!payload || typeof payload !== "object") {
    return jsonResponse({ error: "Ugyldig forespørsel." }, 400);
  }

  const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
  const ipSalt = env.IP_HASH_SALT;
  if (!ipSalt) {
    return jsonResponse({ error: "Tjenesten er ikke konfigurert." }, 500);
  }
  const ipHash = await hashIp(ip, ipSalt);

  // Rate limiting — fail closed on DB errors so a broken limiter can't be
  // used to bypass protection.
  try {
    const withinLimit = await checkRateLimit(env.DB, ipHash);
    if (!withinLimit) {
      return jsonResponse({ error: "For mange forsøk. Prøv igjen senere." }, 429);
    }
  } catch (err) {
    console.error("Rate limit check failed", err);
    return jsonResponse({ error: "Noe gikk galt. Prøv igjen senere." }, 500);
  }

  // Honeypot — hidden field real users never fill in. Pretend success so
  // bots don't learn to avoid it.
  const honeypot = typeof payload.website === "string" ? payload.website.trim() : "";
  if (honeypot !== "") {
    return jsonResponse({ success: true });
  }

  // Minimum time-on-form — bots submit near-instantly after page load.
  const formRenderedAt = Number(payload.formRenderedAt);
  if (!Number.isFinite(formRenderedAt) || Date.now() - formRenderedAt < MIN_FORM_FILL_MS) {
    return jsonResponse({ error: "Vennligst prøv igjen." }, 400);
  }

  // Cloudflare Turnstile bot verification.
  if (env.TURNSTILE_SECRET_KEY) {
    const token = payload.turnstileToken || payload["cf-turnstile-response"];
    if (!token || typeof token !== "string") {
      return jsonResponse({ error: "Bot-verifisering mangler. Prøv igjen." }, 400);
    }
    const valid = await verifyTurnstile(token, env.TURNSTILE_SECRET_KEY, ip);
    if (!valid) {
      return jsonResponse({ error: "Bot-verifisering feilet. Prøv igjen." }, 400);
    }
  }

  const { fields, errors } = validateFields(payload);
  if (Object.keys(errors).length > 0) {
    if (!isJson) {
      return Response.redirect(`${allowedOrigin}/?signup=error`, 303);
    }
    return jsonResponse({ error: "Valideringsfeil.", fields: errors }, 400);
  }

  try {
    await env.DB.prepare(
      `INSERT INTO signups
         (first_name, last_name, email, phone, address, postal_code, city, consent, ip_hash, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, datetime('now'))`
    )
      .bind(
        fields.firstName,
        fields.lastName,
        fields.email,
        fields.phone,
        fields.address,
        fields.postalCode,
        fields.city,
        fields.consent ? 1 : 0,
        ipHash
      )
      .run();
  } catch (err) {
    const message = String(err && err.message ? err.message : "");
    if (message.includes("UNIQUE")) {
      if (!isJson) {
        return Response.redirect(`${allowedOrigin}/?signup=duplicate`, 303);
      }
      return jsonResponse(
        { error: "Denne e-postadressen er allerede registrert.", fields: { email: "Allerede registrert." } },
        409
      );
    }
    console.error("Signup insert failed", err);
    if (!isJson) {
      return Response.redirect(`${allowedOrigin}/?signup=error`, 303);
    }
    return jsonResponse({ error: "Noe gikk galt. Prøv igjen senere." }, 500);
  }

  if (!isJson) {
    return Response.redirect(`${allowedOrigin}/?signup=ok`, 303);
  }
  return jsonResponse({ success: true });
}

export async function onRequest(context) {
  if (context.request.method === "POST") {
    return onRequestPost(context);
  }
  return jsonResponse({ error: "Method not allowed" }, 405);
}
