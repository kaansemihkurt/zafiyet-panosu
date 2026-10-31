"""
Zafiyet İstihbarat Panosu — veri hattı (GitHub Actions, günde 1 kez).

Kaynaklar
  * NVD CVE API 2.0  (https://services.nvd.nist.gov/rest/json/cves/2.0)
      - son N gün içinde yayımlanan CVE'ler (ayrıntı tablosu)
      - KEV kataloğundaki tüm CVE'ler (hasKev) → CVSS puanları
      - son 12 haftanın haftalık yeni CVE sayısı (yalnızca totalResults, resultsPerPage=1)
  * CISA KEV JSON (https://www.cisa.gov/.../known_exploited_vulnerabilities.json)

Çıktı (--out klasörü; Actions'ta "data" dalının çalışma kopyası)
  cves.json   panodaki kayıtlar (son N gün + KEV), KEV bayrağıyla birleştirilmiş
  trend.json  haftalık yeni CVE, haftalık KEV eklemesi, günlük anlık görüntü (snapshot) geçmişi
  meta.json   son çekim zamanı, kaynak durumu, son başarılı çekim
  history/YYYY-MM-DD.json  günlük anlık görüntü özeti (kendi zaman serimiz birikir)

Dayanıklılık: bir kaynak çökerse önceki başarılı dosya korunur ve meta.json'da işaretlenir;
arayüz kullanıcıya "son başarılı veri" uyarısı gösterir.

API anahtarı: NVD_API_KEY ortam değişkeni (yalnızca GitHub Secrets → Actions). İstemciye asla gitmez.
Yalnızca Python standart kütüphanesi kullanılır.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

NVD_URL = os.environ.get("NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
KEV_URL = os.environ.get("KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
API_KEY = os.environ.get("NVD_API_KEY", "").strip()
# NVD hız sınırı: anahtarsız 5 istek / 30 sn, anahtarlı 50 istek / 30 sn
PAUSE = 0.8 if API_KEY else 6.5
UA = "zafiyet-panosu/1.0 (ders projesi; github.com/kaansemihkurt/zafiyet-panosu)"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def nvd_time(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def get_json(url: str, headers: dict | None = None, tries: int = 4) -> dict:
    last = None
    for attempt in range(tries):
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                return json.loads(r.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:  # HTTPError da URLError'dur
            last = e
            code = getattr(e, "code", None)
            if code in (400, 401, 404):
                break  # tekrar denemek anlamsız
            time.sleep(min(30, 6 * (attempt + 1)))
    raise RuntimeError(f"İstek başarısız: {type(last).__name__}: {getattr(last, 'code', '') or last}")


def nvd(params: dict) -> dict:
    q = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None}, safe=":")
    # hasKev / noRejected değersiz parametrelerdir
    q = q.replace("hasKev=1", "hasKev").replace("noRejected=1", "noRejected")
    data = get_json(f"{NVD_URL}?{q}", {"apiKey": API_KEY} if API_KEY else None)
    time.sleep(PAUSE)
    return data


def nvd_all(params: dict, cap: int = 12000) -> list[dict]:
    out, start = [], 0
    while True:
        page = nvd({**params, "resultsPerPage": 2000, "startIndex": start})
        vulns = page.get("vulnerabilities", [])
        out.extend(vulns)
        start += len(vulns)
        if not vulns or start >= page.get("totalResults", 0) or start >= cap:
            return out


# ---------- dönüştürme ----------
SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "NONE": "none"}


def pick_cvss(metrics: dict) -> tuple[float | None, str, str | None]:
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        items = metrics.get(key) or []
        if not items:
            continue
        m = next((x for x in items if x.get("type") == "Primary"), items[0])
        d = m.get("cvssData", {})
        score = d.get("baseScore")
        sev = d.get("baseSeverity") or m.get("baseSeverity")
        if score is not None:
            return float(score), SEV.get(str(sev).upper(), "none"), ver
    return None, "none", None


def vendor_products(cve: dict, limit: int = 4) -> list[str]:
    seen = []
    for conf in cve.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                parts = str(m.get("criteria", "")).split(":")
                if len(parts) > 4:
                    vp = f"{parts[3]}/{parts[4]}".replace("_", " ")
                    if vp not in seen:
                        seen.append(vp)
                if len(seen) >= limit:
                    return seen
    return seen


def compact(v: dict) -> dict:
    c = v.get("cve", v)
    desc = next((d.get("value", "") for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    desc = " ".join(desc.split())
    score, sev, ver = pick_cvss(c.get("metrics", {}) or {})
    cwe = next((d.get("value") for w in c.get("weaknesses", []) or [] for d in w.get("description", []) if str(d.get("value", "")).startswith("CWE-")), None)
    return {
        "id": c.get("id"),
        "pub": str(c.get("published", ""))[:10],
        "score": score,
        "sev": sev,
        "ver": ver,
        "cwe": cwe,
        "desc": desc[:200] + ("…" if len(desc) > 200 else ""),
        "vp": vendor_products(c),
    }


def kev_map(kev: dict) -> dict:
    out = {}
    for v in kev.get("vulnerabilities", []):
        cid = v.get("cveID")
        if cid:
            out[cid] = {
                "added": v.get("dateAdded"),
                "due": v.get("dueDate"),
                "rw": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "name": v.get("vulnerabilityName", ""),
            }
    return out


def week_bounds(now: datetime, n: int = 12) -> list[tuple[datetime, datetime]]:
    """Son n hafta (Pazartesi 00:00 UTC başlangıçlı); son hafta bugün itibarıyla kısmi olabilir."""
    monday = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    weeks = []
    for i in range(n - 1, -1, -1):
        s = monday - timedelta(weeks=i)
        e = min(s + timedelta(days=7) - timedelta(seconds=1), now)
        weeks.append((s, e))
    return weeks


def load(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")


def run(out: Path, days: int) -> int:
    now = utcnow()
    meta_prev = load(out / "meta.json", {})
    cves_prev = load(out / "cves.json", {"items": []})
    trend_prev = load(out / "trend.json", {})
    status = {"nvd": {"ok": False, "error": None}, "kev": {"ok": False, "error": None}}
    last_success = dict(meta_prev.get("lastSuccess", {}))

    # 1) KEV
    kev = None
    try:
        kev_raw = get_json(KEV_URL)
        kev = kev_map(kev_raw)
        if len(kev) < 100:
            raise RuntimeError(f"KEV kataloğu beklenenden küçük ({len(kev)})")
        status["kev"] = {"ok": True, "error": None, "count": len(kev), "catalogVersion": kev_raw.get("catalogVersion")}
        last_success["kev"] = iso(now)
    except Exception as e:  # noqa: BLE001
        status["kev"]["error"] = str(e)[:200]
        print(f"[KEV] HATA: {e}", file=sys.stderr)

    # 2) NVD
    items, weeks = None, None
    try:
        recent = nvd_all({"pubStartDate": nvd_time(now - timedelta(days=days)), "pubEndDate": nvd_time(now), "noRejected": 1})
        in_kev = nvd_all({"hasKev": 1})
        by_id = {}
        for v in recent + in_kev:
            c = compact(v)
            if c["id"]:
                by_id[c["id"]] = c
        items = list(by_id.values())
        weeks = []
        for s, e in week_bounds(now):
            total = nvd({"pubStartDate": nvd_time(s), "pubEndDate": nvd_time(e), "resultsPerPage": 1, "noRejected": 1}).get("totalResults", 0)
            weeks.append({"start": s.strftime("%Y-%m-%d"), "end": e.strftime("%Y-%m-%d"), "total": int(total), "partial": e < s + timedelta(days=7) - timedelta(seconds=1)})
        status["nvd"] = {"ok": True, "error": None, "recent": len(recent), "kevWithCvss": len(in_kev)}
        last_success["nvd"] = iso(now)
    except Exception as e:  # noqa: BLE001
        status["nvd"]["error"] = str(e)[:200]
        print(f"[NVD] HATA: {e}", file=sys.stderr)

    if items is None and kev is None and not cves_prev.get("items"):
        print("Hiçbir kaynak alınamadı ve önceki veri yok.", file=sys.stderr)
        return 2

    # 3) Birleştir (başarısız kaynak için önceki veriyi kullan)
    if items is None:
        items = [{k: v for k, v in it.items() if k != "kev"} for it in cves_prev.get("items", [])]
    if kev is None:
        kev = {it["id"]: it["kev"] for it in cves_prev.get("items", []) if it.get("kev")}
    for it in items:
        k = kev.get(it["id"])
        it["kev"] = {"added": k["added"], "due": k["due"], "rw": k["rw"]} if k else None
        if k and not it["vp"] and (k.get("vendor") or k.get("product")):
            it["vp"] = [f"{k.get('vendor', '')}/{k.get('product', '')}"]
    items.sort(key=lambda x: (x["pub"], x["id"]), reverse=True)

    # 4) Haftalık KEV eklemeleri (KEV'in kendi tarihinden)
    kev_weekly = []
    for s, e in week_bounds(now):
        a, b = s.strftime("%Y-%m-%d"), e.strftime("%Y-%m-%d")
        kev_weekly.append({"start": a, "count": sum(1 for k in kev.values() if k.get("added") and a <= k["added"] <= b)})

    # 5) Anlık görüntü (snapshot): kaynak geçmiş özet vermediği için kendi serimizi biriktiriyoruz
    recent_cut = (now - timedelta(days=days)).strftime("%Y-%m-%d")
    recent_items = [i for i in items if i["pub"] >= recent_cut]
    snap = {
        "date": now.strftime("%Y-%m-%d"),
        "kev": len(kev),
        "recent": len(recent_items),
        "critical": sum(1 for i in recent_items if i["sev"] == "critical"),
        "high": sum(1 for i in recent_items if i["sev"] == "high"),
        "kevRansomware": sum(1 for k in kev.values() if k.get("rw")),
        "nvdOk": status["nvd"]["ok"],
        "kevOk": status["kev"]["ok"],
    }
    write(out / "history" / f"{snap['date']}.json", snap)
    history = sorted((load(p, None) for p in (out / "history").glob("*.json")), key=lambda x: x["date"] if x else "")
    history = [h for h in history if h][-120:]

    write(out / "cves.json", {"generatedAt": iso(now), "windowDays": days, "items": items})
    write(out / "trend.json", {
        "weeks": weeks if weeks is not None else trend_prev.get("weeks", []),
        "kevWeekly": kev_weekly,
        "history": history,
    })
    write(out / "meta.json", {
        "generatedAt": iso(now),
        "lastSuccess": last_success,
        "sources": status,
        "counts": {"items": len(items), "recent": len(recent_items), "kev": len(kev)},
        "links": {"nvd": "https://nvd.nist.gov/developers/vulnerabilities", "kev": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
    })
    print(json.dumps({"items": len(items), "recent": len(recent_items), "kev": len(kev), "status": status}, ensure_ascii=False))
    return 0 if (status["nvd"]["ok"] and status["kev"]["ok"]) else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="datastore")
    ap.add_argument("--days", type=int, default=10)
    code = run(Path(ap.parse_args().out), ap.parse_args().days)
    # 1 = kısmi başarı (bir kaynak çöktü, önceki veri korundu): iş akışı uyarı verir ama yayın sürer
    sys.exit(0 if code in (0, 1) else code)
