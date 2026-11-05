import { getStore } from "@netlify/blobs";
import { createHash, timingSafeEqual } from "node:crypto";

const h = (s) => createHash("sha256").update(String(s)).digest();
const okPw = (pw) => {
  const real = process.env.ORG_PASSWORD;
  return !!real && !!pw && timingSafeEqual(h(pw), h(real));
};
const json = (o, status = 200) =>
  new Response(JSON.stringify(o), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

export default async (req) => {
  const route = new URL(req.url).pathname.replace(/^\/api\//, "");
  const store = getStore("mallco-chapi-2026");

  if (route === "state" && req.method === "GET") {
    return json((await store.get("state", { type: "json" })) || {});
  }
  if (route === "login" && req.method === "POST") {
    const { pw } = await req.json().catch(() => ({}));
    return okPw(pw) ? json({ ok: true }) : json({ ok: false }, 401);
  }
  if (route === "state" && req.method === "PUT") {
    if (!okPw(req.headers.get("x-pw"))) return json({ ok: false }, 401);
    const text = await req.text();
    if (text.length > 4_000_000) return json({ ok: false }, 413);
    let data;
    try { data = JSON.parse(text); } catch { return json({ ok: false }, 400); }
    if (!data || !data.c) return json({ ok: false }, 400);
    await store.setJSON("state", data);
    return json({ ok: true });
  }
  if (route.startsWith("photo/")) {
    const id = route.slice(6);
    if (!/^[a-z0-9]{6,40}$/.test(id)) return json({ ok: false }, 400);
    const ph = getStore("fotos-mallco");
    if (req.method === "GET") {
      const d = await ph.get(id, { type: "arrayBuffer" });
      if (!d) return json({ ok: false }, 404);
      return new Response(d, { headers: { "content-type": "image/jpeg", "cache-control": "public, max-age=31536000, immutable" } });
    }
    if (!okPw(req.headers.get("x-pw"))) return json({ ok: false }, 401);
    if (req.method === "PUT") {
      const buf = await req.arrayBuffer();
      if (buf.byteLength > 400000) return json({ ok: false }, 413);
      await ph.set(id, buf);
      return json({ ok: true });
    }
    if (req.method === "DELETE") { await ph.delete(id); return json({ ok: true }); }
  }
  return json({ ok: false }, 404);
};

export const config = { path: "/api/*" };
