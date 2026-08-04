// Cloudflare Worker: backend for the 서머캠프 후기 board.
//
// Extends the guest-snap-presign Worker with message storage and a
// public/organisers-only split. The SigV4 presigner is carried over
// unchanged — it is proven and needs no external dependencies, so this
// file can still be pasted straight into the dashboard editor.
//
// Photos are uploaded by the browser directly to R2 with a presigned PUT.
// Post records (name, message, visibility, photo keys) live in D1.
//
// Both buckets need a CORS policy of their own (R2 > bucket > Settings >
// CORS Policy). The photo is PUT to R2 by the browser, not by this Worker,
// so the Worker's own CORS headers do not cover it and the upload is
// blocked without one:
//   [{ "AllowedOrigins": ["https://summercamp2026.yellowpenclub.com",
//                         "https://ypcpress.github.io"],
//      "AllowedMethods": ["PUT", "GET"],
//      "AllowedHeaders": ["content-type"],
//      "ExposeHeaders": ["ETag"],
//      "MaxAgeSeconds": 3600 }]
//
// Required binding (Settings > Bindings):
//   DB                     D1 database
//
// Required variables (Settings > Variables and Secrets):
//   R2_ACCESS_KEY_ID       (Secret)
//   R2_SECRET_ACCESS_KEY   (Secret)
//   R2_ACCOUNT_ID          (Text)
//   R2_BUCKET_PUBLIC       (Text)  e.g. "summercamp-photos"  — public access ON
//   R2_BUCKET_PRIVATE      (Text)  e.g. "summercamp-private" — public access OFF
//   R2_PUBLIC_BASE_URL     (Text)  e.g. "https://pub-xxxx.r2.dev"
//   ADMIN_PASSWORD         (Secret)
//
// Schema (run once in the D1 console):
//   CREATE TABLE posts (
//     id         TEXT PRIMARY KEY,
//     name       TEXT    NOT NULL DEFAULT '',
//     message    TEXT    NOT NULL DEFAULT '',
//     images     TEXT    NOT NULL DEFAULT '[]',
//     is_public  INTEGER NOT NULL DEFAULT 1,
//     created_at INTEGER NOT NULL
//   );
//   CREATE INDEX idx_posts_public_created ON posts(is_public, created_at DESC);

const ALLOWED_ORIGINS = [
  'https://summercamp2026.yellowpenclub.com',
  'https://ypcpress.github.io',
  'http://localhost:8000',
];

const MAX_MESSAGE = 4000;
const MAX_NAME    = 20;
const MAX_IMAGES  = 10;
const PAGE_SIZE   = 200;

// Originals are kept under this prefix, always in the bucket with no
// public access. The feed is served the downscaled copy instead.
const ORIG_PREFIX = 'orig/';

// This file is a copy of what runs; editing it does not deploy anything.
// Bump this whenever the file changes, so GET /version tells you whether
// the code in the dashboard is the code you are reading.
const VERSION = '2026-08-04b · originals + video + posters';

/* ---------------- CORS ---------------- */
function corsHeaders(origin) {
  const allowOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Password',
    'Vary': 'Origin',
  };
}

function json(body, origin, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' },
  });
}

/* ---------------- SigV4 (carried over from guest-snap-presign) ---------------- */
function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return toHex(buf);
}

async function hmac(keyMaterial, data) {
  const keyBuf = typeof keyMaterial === 'string' ? new TextEncoder().encode(keyMaterial) : keyMaterial;
  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyBuf, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const dataBuf = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return crypto.subtle.sign('HMAC', cryptoKey, dataBuf);
}

async function presignUrl(env, method, canonicalUri, extraQueryParams, expires = 600) {
  const region = 'auto';
  const service = 's3';
  const host = `${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const credential = `${env.R2_ACCESS_KEY_ID}/${credentialScope}`;

  const queryParams = {
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': credential,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(expires),
    'X-Amz-SignedHeaders': 'host',
    ...extraQueryParams,
  };
  const canonicalQueryString = Object.keys(queryParams)
    .sort()
    .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(queryParams[k])}`)
    .join('&');

  const canonicalHeaders = `host:${host}\n`;
  const signedHeaders = 'host';
  const payloadHash = 'UNSIGNED-PAYLOAD';

  const canonicalRequest = [
    method, canonicalUri, canonicalQueryString, canonicalHeaders, signedHeaders, payloadHash,
  ].join('\n');

  const stringToSign = [
    'AWS4-HMAC-SHA256', amzDate, credentialScope, await sha256Hex(canonicalRequest),
  ].join('\n');

  const kDate = await hmac(`AWS4${env.R2_SECRET_ACCESS_KEY}`, dateStamp);
  const kRegion = await hmac(kDate, region);
  const kService = await hmac(kRegion, service);
  const kSigning = await hmac(kService, 'aws4_request');
  const signature = toHex(await hmac(kSigning, stringToSign));

  return `https://${host}${canonicalUri}?${canonicalQueryString}&X-Amz-Signature=${signature}`;
}

function objectUri(bucket, key) {
  return `/${bucket}/${encodeURIComponent(key).replace(/%2F/g, '/')}`;
}

/* ---------------- helpers ---------------- */
function bucketFor(env, isPublic) {
  return isPublic ? env.R2_BUCKET_PUBLIC : env.R2_BUCKET_PRIVATE;
}

function isAdmin(request, env) {
  const given = request.headers.get('X-Admin-Password') || '';
  const want = env.ADMIN_PASSWORD || '';
  // Reject rather than let an unset secret authenticate everyone.
  if (!want) return false;
  if (given.length !== want.length) return false;
  // Compare every character so the time taken does not reveal the prefix.
  let diff = 0;
  for (let i = 0; i < want.length; i++) diff |= given.charCodeAt(i) ^ want.charCodeAt(i);
  return diff === 0;
}

function rowToPost(row, publicBase) {
  let images = [];
  try { images = JSON.parse(row.images) || []; } catch (e) { images = []; }
  const isPublic = row.is_public === 1;
  return {
    id: row.id,
    name: row.name || '',
    message: row.message || '',
    isPublic,
    createdAt: row.created_at,
    // Public media is served straight from the bucket's public URL.
    // Private media carries only a key here; /admin/posts signs it.
    images: images.map((im) => ({
      key: im.key,
      orig: im.orig || '',
      // A still captured from the video at upload time. It sits beside the
      // display copy, so it follows the same visibility.
      poster: im.poster || '',
      type: im.type === 'video' ? 'video' : 'image',
      url: isPublic && publicBase ? `${publicBase.replace(/\/$/, '')}/${im.key}` : '',
      posterUrl: im.poster && isPublic && publicBase
        ? `${publicBase.replace(/\/$/, '')}/${im.poster}` : '',
    })),
  };
}

// The original's key is only ever useful alongside a signature, so it does
// not travel with the public feed.
function stripOrig(post) {
  return {
    ...post,
    images: post.images.map(({ orig, ...rest }) => ({ ...rest, hasOrig: !!orig })),
  };
}

/* ---------------- endpoints ---------------- */

// Hand back a URL the browser can PUT one file to. A display copy follows
// the post's visibility, so a private one never lands in the bucket that is
// readable by anyone. An original is an archive copy and always goes to the
// private bucket, whatever the post's visibility.
//
// Size is not checked here: with a presigned PUT the bytes go straight to
// R2 and never reach this Worker, so the browser is the only place that can
// hold the line.
async function handlePresign(request, env, origin) {
  const { contentType, isPublic, kind, ext } = await request.json();
  const isVideo = /^video\//.test(contentType || '');
  if (!contentType || !(isVideo || /^image\//.test(contentType))) {
    return json({ error: 'image or video contentType required' }, origin, 400);
  }

  const original = kind === 'original';
  const safeExt = /^[a-z0-9]{1,5}$/i.test(ext || '') ? ext.toLowerCase() : (isVideo ? 'mp4' : 'jpg');
  const stem = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;

  const bucket = original ? env.R2_BUCKET_PRIVATE : bucketFor(env, isPublic !== false);
  const key = original ? `${ORIG_PREFIX}${stem}.${safeExt}` : `${stem}.${safeExt}`;

  // An hour, not the default ten minutes: a 100MB video over mobile data
  // can outlast a short-lived signature and fail at the very end.
  const uploadUrl = await presignUrl(env, 'PUT', objectUri(bucket, key), {}, 3600);
  return json({ uploadUrl, key }, origin);
}

async function handleCreatePost(request, env, origin) {
  const body = await request.json();
  const name = String(body.name || '').trim().slice(0, MAX_NAME);
  const message = String(body.message || '').trim().slice(0, MAX_MESSAGE);
  const isPublic = body.isPublic !== false;

  const images = (Array.isArray(body.images) ? body.images : [])
    .slice(0, MAX_IMAGES)
    .map((im) => ({
      key: String((im && im.key) || ''),
      orig: String((im && im.orig) || ''),
      poster: String((im && im.poster) || ''),
      type: (im && im.type) === 'video' ? 'video' : 'image',
    }))
    .filter((im) => im.key && !im.key.includes('/'))
    .map((im) => ({ ...im, poster: im.poster.includes('/') ? '' : im.poster }))
    // A malformed original reference is dropped on its own rather than
    // taking the whole upload down with it.
    .map((im) => ({ ...im, orig: /^orig\/[^/]+$/.test(im.orig) ? im.orig : '' }));

  if (!message && !images.length) {
    return json({ error: 'message or images required' }, origin, 400);
  }

  const id = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
  await env.DB.prepare(
    'INSERT INTO posts (id, name, message, images, is_public, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(id, name, message, JSON.stringify(images), isPublic ? 1 : 0, Date.now()).run();

  return json({ ok: true, id }, origin);
}

async function handleListPublic(env, origin) {
  const { results } = await env.DB.prepare(
    'SELECT * FROM posts WHERE is_public = 1 ORDER BY created_at DESC LIMIT ?'
  ).bind(PAGE_SIZE).all();
  const items = (results || []).map((r) => stripOrig(rowToPost(r, env.R2_PUBLIC_BASE_URL)));
  return json({ items }, origin);
}

async function handleListAdmin(env, origin) {
  const { results } = await env.DB.prepare(
    'SELECT * FROM posts ORDER BY created_at DESC LIMIT ?'
  ).bind(PAGE_SIZE).all();

  const items = (results || []).map((r) => rowToPost(r, env.R2_PUBLIC_BASE_URL));

  // Anything in the private bucket needs a short-lived signed URL — the
  // display copy of a private post, and every original. One signature
  // each, no network round trip.
  await Promise.all(items.map(async (p) => {
    await Promise.all(p.images.map(async (im) => {
      if (!p.isPublic) {
        im.url = await presignUrl(env, 'GET', objectUri(env.R2_BUCKET_PRIVATE, im.key), {}, 3600);
        if (im.poster) {
          im.posterUrl = await presignUrl(env, 'GET', objectUri(env.R2_BUCKET_PRIVATE, im.poster), {}, 3600);
        }
      }
      if (im.orig) {
        im.origUrl = await presignUrl(env, 'GET', objectUri(env.R2_BUCKET_PRIVATE, im.orig), {}, 3600);
      }
    }));
  }));

  return json({ items }, origin);
}

// No moderation queue by design, so deletion is the way to take something
// down. Removes the photos from R2 as well as the row.
async function handleDelete(request, env, origin) {
  const { id } = await request.json();
  if (!id) return json({ error: 'id required' }, origin, 400);

  const row = await env.DB.prepare('SELECT * FROM posts WHERE id = ?').bind(id).first();
  if (!row) return json({ error: 'not found' }, origin, 404);

  const post = rowToPost(row, env.R2_PUBLIC_BASE_URL);
  const bucket = bucketFor(env, post.isPublic);

  const drop = async (b, key) => {
    try {
      const url = await presignUrl(env, 'DELETE', objectUri(b, key), {});
      await fetch(url, { method: 'DELETE' });
    } catch (e) {
      // A missing object should not block removing the post itself.
      console.error('delete object', key, e);
    }
  };

  await Promise.all(post.images.flatMap((im) => [
    drop(bucket, im.key),
    ...(im.poster ? [drop(bucket, im.poster)] : []),
    ...(im.orig ? [drop(env.R2_BUCKET_PRIVATE, im.orig)] : []),
  ]));

  await env.DB.prepare('DELETE FROM posts WHERE id = ?').bind(id).run();
  return json({ ok: true }, origin);
}

/* ---------------- router ---------------- */
export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    const { pathname } = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(origin) });
    }

    try {
      if (request.method === 'GET' && pathname === '/version') {
        return json({ version: VERSION }, origin);
      }
      if (request.method === 'GET' && (pathname === '/posts' || pathname === '/')) {
        return await handleListPublic(env, origin);
      }
      if (request.method === 'POST' && pathname === '/presign') {
        return await handlePresign(request, env, origin);
      }
      if (request.method === 'POST' && pathname === '/posts') {
        return await handleCreatePost(request, env, origin);
      }

      if (pathname.startsWith('/admin/')) {
        if (!isAdmin(request, env)) return json({ error: 'unauthorized' }, origin, 401);
        if (request.method === 'GET' && pathname === '/admin/posts') {
          return await handleListAdmin(env, origin);
        }
        if (request.method === 'POST' && pathname === '/admin/delete') {
          return await handleDelete(request, env, origin);
        }
      }

      return json({ error: 'not found' }, origin, 404);
    } catch (err) {
      console.error(err);
      return json({ error: String(err) }, origin, 500);
    }
  },
};
