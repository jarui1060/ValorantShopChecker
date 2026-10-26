"""Shared helpers for Riot RSO auth and the Valorant store endpoint.

Used by check_store.py (interactive), bootstrap_cookies.py (one-time local
login to seed a reusable session), and ci_check_store.py (unattended,
cookie-based refresh for the GitHub Action).
"""
import datetime as _dt
import re
import time
from urllib.parse import parse_qs, urlparse

import requests

AUTH_URL = "https://auth.riotgames.com/api/v1/authorization"
AUTHORIZE_URL = (
    "https://auth.riotgames.com/authorize"
    "?redirect_uri=https%3A%2F%2Fplayvalorant.com%2Fopt_in"
    "&client_id=play-valorant-web-prod"
    "&response_type=token%20id_token"
    "&nonce=1&scope=account%20openid"
)
ENTITLEMENTS_URL = "https://entitlements.auth.riotgames.com/api/token/v1"
USERINFO_URL = "https://auth.riotgames.com/userinfo"
VERSION_URL = "https://valorant-api.com/v1/version"
SKINLEVELS_URL = "https://valorant-api.com/v1/weapons/skinlevels"
COMPETITIVE_TIERS_URL = "https://valorant-api.com/v1/competitivetiers"
MAPS_URL = "https://valorant-api.com/v1/maps"
SEASONS_URL = "https://valorant-api.com/v1/seasons"
CLIENT_PLATFORM = (
    "ew0KCSJwbGF0Zm9ybVR5cGUiOiAiUEMiLA0KCSJwbGF0Zm9ybU9TIjogIldpbmRvd3MiLA0KCSJwbGF0Zm9ybU9T"
    "VmVyc2lvbiI6ICIxMC4wLjE5MDQyLjEuMjU2LjY0Yml0IiwNCgkicGxhdGZvcm1DaGlwc2V0IjogIlVua25vd24i"
    "DQp9"
)

TOKEN_PATTERN = re.compile(
    r"access_token=((?:[a-zA-Z]|\d|\.|-|_)*).*id_token=((?:[a-zA-Z]|\d|\.|-|_)*).*expires_in=(\d*)"
)


class AuthError(Exception):
    pass


def login(session: requests.Session, username: str, password: str, code_prompt=input) -> str:
    """Full username/password (+ 2FA) login. Returns an access_token.

    code_prompt lets callers override how a 2FA code is obtained (defaults to
    a blocking input() — not usable from an unattended CI run).
    """
    session.post(
        AUTH_URL,
        json={
            "client_id": "play-valorant-web-prod",
            "nonce": "1",
            "redirect_uri": "https://playvalorant.com/opt_in",
            "response_type": "token id_token",
        },
    )

    resp = session.put(
        AUTH_URL, json={"type": "auth", "username": username, "password": password}
    ).json()

    if resp.get("type") == "multifactor":
        method = resp["multifactor"].get("method", "email")
        code = code_prompt(f"Enter your {method} 2FA code: ").strip()
        resp = session.put(
            AUTH_URL, json={"type": "multifactor", "code": code, "rememberDevice": False}
        ).json()

    if "error" in resp:
        error = resp["error"]
        hint = {
            "auth_failure": "the username or password is wrong (use your Riot login "
            "email/username, not your in-game name).",
            "rate_limited": "too many attempts — wait a while before retrying.",
        }.get(error, "Riot rejected the login (possibly a captcha challenge this script can't solve).")
        raise AuthError(f"Login failed: {error} — {hint}")
    if resp.get("type") != "response":
        raise AuthError(f"Login failed, unexpected response: {resp}")

    uri = resp["response"]["parameters"]["uri"]
    match = TOKEN_PATTERN.findall(uri)
    if not match:
        raise AuthError(f"Could not parse tokens from response: {uri}")
    return match[0][0]  # access_token


def extract_access_token(url: str) -> str:
    """Pulls access_token out of a playvalorant.com/opt_in redirect URL."""
    fragment = urlparse(url.strip()).fragment
    params = parse_qs(fragment)
    if "access_token" not in params:
        raise AuthError(
            "Could not find access_token in that URL. Make sure you pasted the full "
            "address bar contents after logging in, including the part after '#'."
        )
    return params["access_token"][0]


def reauth_with_cookies(session: requests.Session) -> str | None:
    """Silently mints a fresh access token from cookies already on the session
    (no username/password/2FA needed). Returns None if the cookies are no
    longer valid and a full interactive login is required.
    """
    resp = session.get(AUTHORIZE_URL, allow_redirects=False, timeout=15)
    if resp.status_code >= 400:
        raise AuthError(f"Riot a refusé la connexion (HTTP {resp.status_code}).")
    location = resp.headers.get("Location", "")
    if "access_token" not in location:
        return None
    if urlparse(location).hostname != "playvalorant.com":
        raise AuthError("Riot a renvoyé une redirection de connexion inattendue.")
    return extract_access_token(location)


def checked_json(response: requests.Response, context: str) -> dict:
    """Parses a response as JSON, or raises with a clear diagnostic if it isn't."""
    if not response.ok:
        raise AuthError(f"[{context}] Riot a refusé la requête (HTTP {response.status_code}).")
    try:
        return response.json()
    except ValueError:
        raise AuthError(f"[{context}] Réponse Riot illisible (HTTP {response.status_code}).") from None


def get_client_version() -> str:
    try:
        return requests.get(VERSION_URL, timeout=10).json()["data"]["riotClientVersion"]
    except Exception:
        return "release-08.05-shipping-9-1234567"  # fallback if valorant-api.com is down


def get_skin_names() -> dict:
    """Maps item (skin level) UUIDs -> display names, best-effort."""
    try:
        data = requests.get(SKINLEVELS_URL, params={"language": "fr-FR"}, timeout=10).json()["data"]
        return {item["uuid"].lower(): item["displayName"] for item in data}
    except Exception:
        return {}


def game_headers(session: requests.Session, access_token: str) -> tuple[dict, str]:
    """Builds the auth headers for pd.{region} game endpoints. Returns (headers, puuid)."""
    headers = {"Authorization": f"Bearer {access_token}"}
    entitlements_resp = session.post(ENTITLEMENTS_URL, headers=headers, json={}, timeout=20)
    entitlements_token = checked_json(entitlements_resp, "entitlements")["entitlements_token"]

    userinfo_resp = session.post(USERINFO_URL, headers=headers, json={}, timeout=20)
    puuid = checked_json(userinfo_resp, "userinfo")["sub"]

    headers["X-Riot-Entitlements-JWT"] = entitlements_token
    headers["X-Riot-ClientVersion"] = get_client_version()
    headers["X-Riot-ClientPlatform"] = CLIENT_PLATFORM
    return headers, puuid


def get_tier_names() -> dict:
    """Maps competitive tier number -> readable name, e.g. 21 -> 'Immortal 1'."""
    try:
        episodes = requests.get(COMPETITIVE_TIERS_URL, timeout=10).json()["data"]
        # The last episode holds the current tier naming.
        tiers = episodes[-1]["tiers"]
        return {t["tier"]: t["tierName"].title() for t in tiers}
    except Exception:
        return {}


def get_map_names() -> dict:
    """Maps a map's internal path (mapUrl) -> display name, e.g. Ascent."""
    try:
        data = requests.get(MAPS_URL, timeout=10).json()["data"]
        return {m["mapUrl"]: m["displayName"] for m in data if m.get("mapUrl")}
    except Exception:
        return {}


# --- Low-level game endpoints (take prebuilt headers + puuid, so a caller can
# --- reuse one auth handshake across several calls) ---

def store_front(session: requests.Session, headers: dict, puuid: str, region: str) -> dict:
    # v2 (GET) was deprecated by Riot in favor of v3 (POST).
    store_url = f"https://pd.{region}.a.pvp.net/store/v3/storefront/{puuid}"
    return checked_json(session.post(store_url, headers=headers, json={}, timeout=20), "store")


def competitive_updates(
    session: requests.Session, headers: dict, puuid: str, region: str, count: int = 5
) -> dict:
    url = (
        f"https://pd.{region}.a.pvp.net/mmr/v1/players/{puuid}/competitiveupdates"
        f"?startIndex=0&endIndex={count}&queue=competitive"
    )
    return checked_json(session.get(url, headers=headers), "competitive updates")


def player_mmr(session: requests.Session, headers: dict, puuid: str, region: str) -> dict:
    url = f"https://pd.{region}.a.pvp.net/mmr/v1/players/{puuid}"
    return checked_json(session.get(url, headers=headers), "mmr")


def match_details(session: requests.Session, headers: dict, region: str, match_id: str) -> dict:
    url = f"https://pd.{region}.a.pvp.net/match-details/v1/matches/{match_id}"
    return checked_json(session.get(url, headers=headers, timeout=20), "match details")


# --- access_token-based wrappers (used by CI / bootstrap, one call each) ---

def get_current_act() -> tuple:
    """Returns (act_uuid, act_start_millis) for the currently active act, or (None, None)."""
    try:
        seasons = requests.get(SEASONS_URL, timeout=10).json()["data"]
        now = _dt.datetime.now(_dt.timezone.utc)
        for s in seasons:
            start = _dt.datetime.fromisoformat(s["startTime"].replace("Z", "+00:00"))
            end = _dt.datetime.fromisoformat(s["endTime"].replace("Z", "+00:00"))
            # Acts have a parent episode; episodes (parentUuid=None) also match the
            # date window, so require parentUuid to pick the act specifically.
            if s.get("parentUuid") and start <= now < end:
                return s["uuid"], int(start.timestamp() * 1000)
    except Exception:
        pass
    return None, None


def paged_competitive_matches(
    session: requests.Session,
    headers: dict,
    puuid: str,
    region: str,
    act_start_millis,
    hard_cap: int = 300,
) -> list:
    """Pages competitiveupdates to collect every ranked match in the current act.

    Riot allows at most 20 entries per request, so this walks the history 20 at
    a time and stops once matches predate the act (or the history runs out).
    """
    collected = []
    start = 0
    while start < hard_cap:
        end = start + 20
        url = (
            f"https://pd.{region}.a.pvp.net/mmr/v1/players/{puuid}/competitiveupdates"
            f"?startIndex={start}&endIndex={end}&queue=competitive"
        )
        try:
            batch = checked_json(session.get(url, headers=headers), "competitive updates").get(
                "Matches"
            ) or []
        except AuthError:
            break
        if not batch:
            break
        for m in batch:
            if act_start_millis and m.get("MatchStartTime", 0) < act_start_millis:
                return collected  # reached the previous act; done
            collected.append(m)
        start = end
    return collected


def compute_match_stats(
    session: requests.Session,
    headers: dict,
    puuid: str,
    region: str,
    matches: list,
    progress: bool = False,
) -> dict:
    """Winrate + average K/D over the given ranked matches.

    Fetches per-match details for each game and reads both the K/D (from the
    player's stats) and win/loss (from the player's team) out of the same
    responses, so both figures cover exactly the same set of games. A failed
    fetch (e.g. a rate limit) is retried once with a short backoff, then skipped.
    """
    kills = deaths = counted = wins = losses = draws = 0
    per_match = []  # one record per counted game, most-recent first
    total = len(matches)
    for i, m in enumerate(matches, 1):
        match_id = m.get("MatchID")
        if not match_id:
            continue
        if progress:
            print(f"  fetching match {i}/{total}...", end="\r", flush=True)
        details = None
        for attempt in range(2):
            try:
                details = match_details(session, headers, region, match_id)
                break
            except AuthError:
                if attempt == 0:
                    time.sleep(2)  # brief backoff, likely a transient rate limit
        if details is None:
            continue  # skip a match that keeps erroring rather than aborting
        players = details.get("players", [])
        me = next((p for p in players if p.get("subject") == puuid), None)
        if not me:
            continue
        stats = me.get("stats", {})
        k = stats.get("kills", 0)
        d = stats.get("deaths", 0)
        a = stats.get("assists", 0)
        kills += k
        deaths += d
        counted += 1

        teams = details.get("teams", [])
        my_team = next((t for t in teams if t.get("teamId") == me.get("teamId")), None)
        if my_team is None:
            result = "draw"
            draws += 1
        elif my_team.get("won"):
            result = "win"
            wins += 1
        elif len(teams) == 2 and teams[0].get("won") == teams[1].get("won"):
            result = "draw"
            draws += 1
        else:
            result = "loss"
            losses += 1

        my_rounds = my_team.get("roundsWon", 0) if my_team else 0
        enemy_rounds = max(
            (t.get("roundsWon", 0) for t in teams if t is not my_team), default=0
        )
        rounds_total = sum(t.get("roundsWon", 0) for t in teams) or (my_rounds + enemy_rounds)
        acs = round(stats.get("score", 0) / rounds_total) if rounds_total else 0

        # Scoreboard placement = rank of this player's combat score among all 10.
        ranked = sorted(players, key=lambda p: p.get("stats", {}).get("score", 0), reverse=True)
        placement = next(
            (idx for idx, p in enumerate(ranked, 1) if p.get("subject") == puuid), 0
        )

        per_match.append(
            {
                "map_id": m.get("MapID", ""),
                "rr": m.get("RankedRatingEarned", 0),
                "result": result,
                "my_rounds": my_rounds,
                "enemy_rounds": enemy_rounds,
                "kills": k,
                "deaths": d,
                "assists": a,
                "acs": acs,
                "placement": placement,
                "players": len(players),
            }
        )

    if progress and total:
        print(" " * 40, end="\r")  # clear the progress line

    kd = (kills / deaths) if deaths else float(kills)
    return {
        "kills": kills,
        "deaths": deaths,
        "kd": kd,
        "games": counted,
        "wins": wins,
        "losses": losses,
        "draws": draws,
        "per_match": per_match,
    }


def format_season_stats_lines(stats: dict) -> list[str]:
    """Human-readable winrate + average K/D summary over the sampled ranked games."""
    lines = []
    decisive = stats["wins"] + stats["losses"]
    if decisive:
        wr = stats["wins"] / decisive * 100
        draw_note = f", {stats['draws']}D" if stats["draws"] else ""
        lines.append(
            f"**Winrate**: {wr:.0f}% ({stats['wins']}W / {stats['losses']}L{draw_note} "
            f"over {stats['games']} ranked games this act)"
        )
    else:
        lines.append("**Winrate**: no ranked match data available.")

    if stats["games"]:
        lines.append(
            f"**Avg K/D**: {stats['kd']:.2f} "
            f"({stats['kills']}K / {stats['deaths']}D over {stats['games']} ranked games this act)"
        )
    else:
        lines.append("**Avg K/D**: no ranked match data available.")
    return lines


def fetch_store(session: requests.Session, access_token: str, region: str) -> dict:
    """Given a valid access token, fetches entitlements + puuid + the store."""
    headers, puuid = game_headers(session, access_token)
    return store_front(session, headers, puuid, region)


def fetch_competitive(
    session: requests.Session, access_token: str, region: str, count: int = 5
) -> dict:
    """Fetches the player's recent competitive updates (rank + RR per match)."""
    headers, puuid = game_headers(session, access_token)
    return competitive_updates(session, headers, puuid, region, count)


def format_store_lines(store: dict) -> list[str]:
    """Human-readable lines describing the store: daily offers + featured bundle."""
    if "SkinsPanelLayout" not in store:
        raise AuthError("Riot n'a pas renvoyé la boutique attendue.")

    names = get_skin_names()
    lines = []

    panel = store["SkinsPanelLayout"]
    offers = panel.get("SingleItemOffers", [])
    seconds_left = panel.get("SingleItemOffersRemainingDurationInSeconds", 0)
    h, r = divmod(seconds_left, 3600)
    m = r // 60
    lines.append(f"🛒 **Ta boutique VALORANT** · renouvellement dans {h} h {m} min")
    for offer_id in offers:
        lines.append(f"- {names.get(offer_id.lower(), offer_id)}")

    featured = store.get("FeaturedBundle") or {}
    # v3 returns a "Bundles" list; older v2-style responses had a single "Bundle".
    bundles = featured.get("Bundles") or ([featured["Bundle"]] if "Bundle" in featured else [])
    for bundle in bundles:
        remaining = bundle.get(
            "DurationRemainingInSeconds", featured.get("BundleRemainingDurationInSeconds", 0)
        )
        h, r = divmod(remaining, 3600)
        m = r // 60
        lines.append(f"\n**Collection en vedette** · fin dans {h} h {m} min")
        for entry in bundle.get("Items", []):
            item_id = entry["Item"]["ItemID"]
            lines.append(f"- {names.get(item_id.lower(), item_id)} ({entry['BasePrice']} VP avant remise)")

    return lines


def _ordinal(n: int) -> str:
    """1 -> '1st', 2 -> '2nd', 11 -> '11th', etc."""
    if not n:
        return "?"
    if 10 <= n % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def format_current_rank_line(comp: dict) -> str:
    """Current rank + RR, from the most recent competitive update."""
    matches = comp.get("Matches") or []
    if not matches:
        return "**Current rank**: no recent competitive matches found."
    latest = matches[0]
    tier = latest.get("TierAfterUpdate", 0)
    rr = latest.get("RankedRatingAfterUpdate", 0)
    tier_name = get_tier_names().get(tier, f"Tier {tier}")
    return f"**Current rank**: {tier_name} — {rr} RR"


def format_recent_matches_lines(per_match: list, count: int = 5) -> list[str]:
    """Detailed readout of the most recent games: result, KDA, ACS, placement, RR."""
    shown = per_match[:count]
    if not shown:
        return ["**Recent matches**: no ranked match data available."]

    map_names = get_map_names()
    lines = [f"**Last {len(shown)} competitive matches**:"]
    for rec in shown:
        map_name = map_names.get(rec["map_id"], rec["map_id"] or "Unknown map")
        result = {"win": "Win", "loss": "Loss", "draw": "Draw"}.get(rec["result"], "?")
        rr = rec["rr"]
        rr_str = f"+{rr}" if rr >= 0 else str(rr)
        kda = f"{rec['kills']}/{rec['deaths']}/{rec['assists']}"
        place = _ordinal(rec["placement"])
        lines.append(
            f"- {map_name}: {result} {rec['my_rounds']}-{rec['enemy_rounds']} | "
            f"{kda} KDA | {rec['acs']} ACS | {place} of {rec['players']} | {rr_str} RR"
        )
    return lines


def cookies_to_dict(session: requests.Session) -> dict:
    """Serializes the auth.riotgames.com cookies needed for reauth_with_cookies."""
    return {
        c.name: c.value
        for c in session.cookies
        if c.domain.lstrip(".") == "riotgames.com" or c.domain.endswith(".riotgames.com")
    }


def cookies_from_dict(session: requests.Session, cookies: dict) -> None:
    for name, value in cookies.items():
        session.cookies.set(name, value, domain="auth.riotgames.com")
