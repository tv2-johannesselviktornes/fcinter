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
  fullName: 150,
  email: 254,
  address: 300,
};

const MAX_AGE_YEARS = 120;
const JUNIOR_MAX_AGE_YEARS = 12; // "Junior (0-12 år)" per membership pricing

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

function parseBirthDate(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;

  const [year, month, day] = value.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  // Reject overflow dates like 2024-02-30 (JS Date normalizes them instead of erroring).
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) {
    return null;
  }

  const now = new Date();
  if (date.getTime() > now.getTime()) return null;

  let age = now.getUTCFullYear() - date.getUTCFullYear();
  const monthDiff = now.getUTCMonth() - date.getUTCMonth();
  if (monthDiff < 0 || (monthDiff === 0 && now.getUTCDate() < date.getUTCDate())) {
    age--;
  }
  if (age < 0 || age > MAX_AGE_YEARS) return null;

  return { isoDate: value, age };
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

const JMAP_USING = [
  "urn:ietf:params:jmap:core",
  "urn:ietf:params:jmap:mail",
  "urn:ietf:params:jmap:submission",
];

async function jmapCall(apiUrl, token, methodCalls) {
  const res = await fetch(apiUrl, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ using: JMAP_USING, methodCalls }),
  });
  if (!res.ok) {
    throw new Error(`JMAP request failed with status ${res.status}`);
  }
  const data = await res.json();
  const resultsByCallId = {};
  for (const [methodName, args, callId] of data.methodResponses) {
    if (methodName === "error") {
      throw new Error(`JMAP method error (${callId}): ${JSON.stringify(args)}`);
    }
    resultsByCallId[callId] = args;
  }
  return resultsByCallId;
}

function buildConfirmationEmailText(fields) {
  const isJunior = fields.membershipType === "junior";
  const membershipLabel = isJunior ? "Junior (0-12 år)" : "Senior";
  const amount = isJunior ? "300 NOK" : "400 NOK";

  return [
    `Hei ${fields.fullName},`,
    "",
    "Takk for at du meldte deg inn i Inter Club Norvegia for sesongen 2026/27!",
    "",
    `Medlemskap: ${membershipLabel}`,
    "",
    "Betalingsinformasjon:",
    "Kontonummer: 9522 07 06975",
    `Beløp: ${amount}`,
    "",
    "Vi ser frem til å ha deg med i klubben!",
    "",
    "Hilsen Inter Club Norvegia",
  ].join("\n");
}

// Sends a confirmation email via Fastmail's JMAP API (plain HTTPS calls,
// no SMTP client needed). Optional: silently no-ops if FASTMAIL_API_TOKEN
// isn't configured, and never throws — a Fastmail hiccup must never affect
// the signup itself, which is already safely recorded in D1 by this point.
async function sendConfirmationEmail(env, toEmail, fields) {
  if (!env.FASTMAIL_API_TOKEN) return;

  try {
    const sessionRes = await fetch("https://api.fastmail.com/jmap/session", {
      headers: { Authorization: `Bearer ${env.FASTMAIL_API_TOKEN}` },
    });
    if (!sessionRes.ok) {
      throw new Error(`JMAP session request failed with status ${sessionRes.status}`);
    }
    const session = await sessionRes.json();
    const accountId = session.primaryAccounts && session.primaryAccounts["urn:ietf:params:jmap:mail"];
    const apiUrl = session.apiUrl;
    if (!accountId || !apiUrl) {
      throw new Error("JMAP session response missing accountId or apiUrl");
    }

    const lookup = await jmapCall(apiUrl, env.FASTMAIL_API_TOKEN, [
      ["Identity/get", { accountId, ids: null }, "identities"],
      ["Mailbox/get", { accountId, properties: ["id", "role"] }, "mailboxes"],
    ]);

    const identities = (lookup.identities && lookup.identities.list) || [];
    const preferredFrom = (env.FASTMAIL_FROM_EMAIL || "").toLowerCase();
    const identity =
      identities.find((candidate) => candidate.email.toLowerCase() === preferredFrom) || identities[0];
    if (!identity) {
      throw new Error("No Fastmail identity available to send from");
    }

    const mailboxes = (lookup.mailboxes && lookup.mailboxes.list) || [];
    const draftsId = (mailboxes.find((mailbox) => mailbox.role === "drafts") || {}).id;
    const sentId = (mailboxes.find((mailbox) => mailbox.role === "sent") || {}).id;
    if (!draftsId) {
      throw new Error("No Drafts mailbox found on Fastmail account");
    }

    const submitMethodCalls = [
      [
        "Email/set",
        {
          accountId,
          create: {
            draft1: {
              mailboxIds: { [draftsId]: true },
              keywords: { $draft: true, $seen: true },
              from: [{ email: identity.email, name: identity.name || "Inter Club Norvegia" }],
              to: [{ email: toEmail }],
              subject: "Bekreftelse: Innmelding Inter Club Norvegia 2026/27",
              bodyValues: { body1: { value: buildConfirmationEmailText(fields), charset: "utf-8" } },
              textBody: [{ partId: "body1", type: "text/plain" }],
            },
          },
        },
        "email",
      ],
      [
        "EmailSubmission/set",
        {
          accountId,
          create: {
            sub1: {
              emailId: "#draft1",
              identityId: identity.id,
            },
          },
          ...(sentId
            ? {
                onSuccessUpdateEmail: {
                  "#sub1": {
                    "keywords/$draft": null,
                    [`mailboxIds/${draftsId}`]: null,
                    [`mailboxIds/${sentId}`]: true,
                  },
                },
              }
            : { onSuccessDestroyEmail: ["#sub1"] }),
        },
        "submission",
      ],
    ];

    const submitResult = await jmapCall(apiUrl, env.FASTMAIL_API_TOKEN, submitMethodCalls);
    const submission = submitResult.submission;
    if (submission && submission.notCreated && submission.notCreated.sub1) {
      throw new Error(`EmailSubmission/set rejected: ${JSON.stringify(submission.notCreated.sub1)}`);
    }
  } catch (err) {
    console.error("Fastmail confirmation email failed", err);
  }
}

function validateFields(payload) {
  const fullName = sanitizeText(payload.fullName, MAX_LENGTHS.fullName);
  const email = sanitizeText(payload.email, MAX_LENGTHS.email).toLowerCase();
  const address = sanitizeText(payload.address, MAX_LENGTHS.address);
  const consent = payload.consent === true || payload.consent === "on" || payload.consent === "true";
  const birthDate = parseBirthDate(typeof payload.birthDate === "string" ? payload.birthDate.trim() : "");

  const fields = {
    fullName,
    email,
    address,
    consent,
    birthDate: birthDate ? birthDate.isoDate : "",
    membershipType: birthDate ? (birthDate.age <= JUNIOR_MAX_AGE_YEARS ? "junior" : "senior") : "",
  };
  const errors = {};

  if (!fullName) errors.fullName = "Fullt navn er påkrevd.";
  if (!isValidEmail(email)) errors.email = "Gyldig e-postadresse er påkrevd.";
  if (!birthDate) errors.birthDate = "Gyldig fødselsdato er påkrevd.";
  if (!address) errors.address = "Adresse er påkrevd (brukes for å sende medlemspakken).";
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
         (full_name, email, birth_date, membership_type, address, consent, ip_hash, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now'))`
    )
      .bind(
        fields.fullName,
        fields.email,
        fields.birthDate,
        fields.membershipType,
        fields.address,
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

  // Runs after the response is sent — a slow or failed email must never
  // delay or fail the signup itself, which is already safely in D1.
  context.waitUntil(sendConfirmationEmail(env, fields.email, fields));

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
