"""Publish the EU shop to Discord and retain rotated Riot cookies encrypted."""
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken
import requests

from valorant_auth import (
    AuthError, cookies_from_dict, cookies_to_dict, fetch_store,
    format_store_lines, reauth_with_cookies,
)


class CheckerError(Exception):
    """A diagnostic that is safe to display without credentials."""


def parse_cookies(value: str) -> dict:
    try:
        cookies = json.loads(value)
    except (ValueError, TypeError):
        raise CheckerError('RIOT_COOKIES doit contenir un JSON comme {"ssid":"..."}.') from None
    if (not isinstance(cookies, dict) or not cookies.get("ssid")
            or any(not isinstance(k, str) or not isinstance(v, str)
                   for k, v in cookies.items())):
        raise CheckerError("RIOT_COOKIES doit contenir un cookie ssid non vide.")
    ssid = cookies["ssid"].strip()
    if ssid.lower().startswith("ssid="):
        ssid = ssid.split("=", 1)[1].strip()
    if not ssid or "..." in ssid or "…" in ssid:
        raise CheckerError("Le ssid est vide ou tronqué ; copie sa valeur complète dans GitHub.")
    if ";" in ssid or any(character.isspace() for character in ssid):
        raise CheckerError("Le ssid contient un séparateur ou des espaces ; copie uniquement sa valeur complète.")
    cookies["ssid"] = ssid
    return cookies


def session_cipher(seed: dict) -> Fernet:
    # ssid is a high-entropy credential, not a human-chosen password.
    key = hashlib.sha256(b"valorant-session-v1\0" + seed["ssid"].encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def load_session(seed: dict, path: Path) -> dict:
    if path.is_file():
        try:
            return parse_cookies(session_cipher(seed).decrypt(path.read_bytes()).decode())
        except (InvalidToken, OSError, UnicodeError, CheckerError):
            print("Sauvegarde incompatible avec le secret actuel ; utilisation du secret.")
    return seed


def save_session(seed: dict, cookies: dict, path: Path) -> None:
    payload = session_cipher(seed).encrypt(json.dumps(cookies).encode())
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_bytes(payload)
    temporary.chmod(0o600)
    temporary.replace(path)


def validate_webhook(value: str) -> bool:
    try:
        url = urlsplit(value)
        return (url.scheme == "https" and url.hostname in {"discord.com", "discordapp.com"}
                and url.path.startswith("/api/webhooks/")
                and not url.username and not url.password)
    except ValueError:
        return False


def post_to_discord(webhook_url: str, content: str) -> None:
    for offset in range(0, len(content), 2000):
        try:
            response = requests.post(
                webhook_url, params={"wait": "true"},
                json={"content": content[offset:offset + 2000],
                      "allowed_mentions": {"parse": []}}, timeout=20,
            )
        except requests.RequestException:
            raise CheckerError("Impossible de joindre Discord ; aucun envoi confirmé.") from None
        if not response.ok:
            raise CheckerError(f"Discord a refusé le message (HTTP {response.status_code}).")
        try:
            confirmed = response.json().get("id")
        except (ValueError, AttributeError):
            confirmed = None
        if not confirmed:
            raise CheckerError("Discord n'a pas confirmé l'enregistrement du message.")


def main() -> int:
    webhook = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
    if not validate_webhook(webhook):
        print("Le secret DISCORD_WEBHOOK_URL est absent ou incorrect.", file=sys.stderr)
        return 1
    try:
        seed = parse_cookies(os.environ.get("RIOT_COOKIES", ""))
        region = os.environ.get("REGION", "eu").strip().lower()
        if region not in {"eu", "na", "ap", "kr", "br", "latam"}:
            raise CheckerError("La région configurée est incorrecte.")
        path = Path(os.environ.get("RIOT_SESSION_FILE", "../.state/riot-session.enc"))
        with requests.Session() as session:
            cookies_from_dict(session, load_session(seed, path))
            token = reauth_with_cookies(session)
            if not token:
                raise CheckerError(
                    "Riot n'a pas délivré de jeton de connexion ; cela ne prouve pas "
                    "que le cookie a expiré."
                )
            # Preserve rotation even if fetching the store or delivering it fails.
            save_session(seed, cookies_to_dict(session), path)
            store = fetch_store(session, token, region)
            panel = store.get("SkinsPanelLayout") if isinstance(store, dict) else None
            offers = panel.get("SingleItemOffers") if isinstance(panel, dict) else None
            if not isinstance(offers, list) or not offers or not all(isinstance(x, str) for x in offers):
                raise CheckerError("Riot n'a pas renvoyé les offres de la boutique attendues.")
            content = "\n".join(format_store_lines(store))
        post_to_discord(webhook, content)
    except (CheckerError, AuthError) as error:
        message = str(error)
    except requests.RequestException:
        message = "Connexion à Riot impossible ou délai dépassé. Le prochain passage réessaiera."
    except Exception:
        # No response bodies, request URLs, tokens, or cookies in logs.
        message = "Erreur inattendue du checker ; aucune donnée de connexion n'est affichée."
    else:
        print("Boutique récupérée ; message enregistré par Discord.")
        return 0
    print(message, file=sys.stderr)
    try:
        post_to_discord(webhook, "⚠️ Boutique VALORANT : " + message)
    except CheckerError:
        print("L'alerte n'a pas pu être envoyée à Discord.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
