import os
import sys
import re
import json
import urllib.request
from typing import Optional, List

# --- Constants ---
THALIAK_REPO = "4e9a232b"
THALIAK_API = f"https://thaliak.xiv.dev/api/v2beta/repositories/{THALIAK_REPO}/patches"
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSIONS_FILE = os.path.join(BASE_DIR, "automation", "ffxiv_versions_global.json")

# --- Utilities ---


def fetch_url(url, is_json=False):
    print(f"Fetching {url}...", file=sys.stderr)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            content = response.read().decode("utf-8")
            if is_json:
                return json.loads(content)
            return content
    except urllib.error.HTTPError as e:
        if e.code == 503:
            print(
                f"  Received 503 for {url}. Maintenance mode. Reading body anyway...",
                file=sys.stderr,
            )
            try:
                content = e.read().decode("utf-8")
                if is_json:
                    return json.loads(content)
                return content
            except Exception:
                return None
        else:
            print(f"  HTTP Error {e.code}: {e.reason}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  Error fetching {url}: {e}", file=sys.stderr)
        return None


# --- Version Info Helpers ---


def get_version_sort_key(v):
    """
    Generates a sortable key for FFXIV versions.
    Handles both strings (e.g., '7.05h2') and dicts containing 'retail_version'.
    """
    if isinstance(v, dict):
        v = v.get("retail_version", "0.0")
    # Using a list of (type_priority, value) tuples to avoid comparing list vs int
    # Priorities: 0 for numeric, 1 for alphabetic
    parts = re.findall(r"(\d+|[a-zA-Z]+)", v)
    return [(0, int(p)) if p.isdigit() else (1, [ord(c) for c in p]) for p in parts]


def load_versions() -> List[dict]:
    """Loads all registered versions from the global registry."""
    if os.path.exists(VERSIONS_FILE):
        try:
            with open(VERSIONS_FILE, "r") as f:
                data = json.load(f)
                if isinstance(data, list):
                    data.sort(key=get_version_sort_key)
                    return data
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Failed to load versions file: {e}", file=sys.stderr)
    return []


def get_latest_version_entry() -> Optional[dict]:
    """Returns the most recent version entry from the version file."""
    data = load_versions()
    return data[-1] if data else None


def fetch_latest_thaliak_patch() -> Optional[str]:
    """
    Fetches the latest date-based version string from the Thaliak API.
    """
    data = fetch_url(THALIAK_API, is_json=True)
    if not data or "patches" not in data or not data["patches"]:
        return None
    return data["patches"][-1]["version_string"]


# --- Lodestone Scraper ---


def parse_lodestone_news_list(html):
    """
    Parses the Lodestone news list to extract news items (URL, Title, and Timestamp).
    Handles the structure found on both the news category and the main landing page.
    """
    if not html:
        return []

    # This pattern captures the link and the title following it within the same list item structure.
    # It accounts for the multi-line whitespace and optional tags like [Maintenance].
    # Timestamp is optional as fallback pages may not have the JS helper.
    pattern = re.compile(
        r'<a [^>]*href="(?P<url>/lodestone/news/detail/[^"]+)"[^>]*>.*?<p [^>]*class="news__list--title"[^>]*>(?P<title_content>.*?)</p>(?:.*?ldst_strftime\((?P<timestamp>\d+))?',
        re.DOTALL | re.I,
    )

    items = []
    for match in pattern.finditer(html):
        url = "https://na.finalfantasyxiv.com" + match.group("url")
        # Clean title content of tags and whitespace
        content = match.group("title_content")
        title = re.sub(r"<[^>]+>", "", content).strip()
        timestamp = int(match.group("timestamp")) if match.group("timestamp") else 0
        items.append({"url": url, "title": title, "timestamp": timestamp})

    return items


def extract_patch_version(html):
    """Extracts the 'X.XX' patch version from maintenance detail HTML."""
    if not html or not (m := re.search(r"patch\s+(\d+\.\d+)", html, re.I)):
        return None
    v = m.group(1)
    v = v + "0" if len(v.split(".")[1]) == 1 else v
    return v + "h" if "HotFixes" in html else v

def is_maintenance_post(title):
    """Returns True if the title represents a primary world maintenance post."""
    t = title.lower()
    return "all worlds" in t and "maintenance" in t and "follow-up" not in t


def format_retail_version(v, count):
    """Formats the version with hotfix suffixes: 7.41, 7.41h, 7.41h2, etc."""
    if count <= 1:
        return v
    return f"{v}h{count - 1 if count > 2 else ''}"


def scrape_latest_maintenance():
    """
    Scrapes the Lodestone to find the most recent 'All Worlds Maintenance' post.
    """
    # Step 1: News Category
    url = "https://na.finalfantasyxiv.com/lodestone/news/category/2"
    html = fetch_url(url)

    # Step 2: Fallback to Landing Page (common during 503 maintenance)
    if not html:
        url = "https://na.finalfantasyxiv.com/lodestone/"
        html = fetch_url(url)

    if not html:
        return None

    news_items = parse_lodestone_news_list(html)

    for item in news_items:
        title = item["title"]
        link = item["url"]

        if not is_maintenance_post(title):
            continue

        detail_html = fetch_url(link)
        version = extract_patch_version(detail_html)

        if version:
            # We assume the first (most recent) valid maintenance post
            # with a patch version is our target.
            return {"retail_version": version, "title": title, "url": link}

    return None


def get_version_info() -> Optional[dict]:
    """
    Returns the latest version information by combining Thaliak and Lodestone data.
    """
    date_new = fetch_latest_thaliak_patch()
    maintenance = scrape_latest_maintenance()

    if not maintenance and not date_new:
        return None

    return {
        "retail_version": maintenance["retail_version"] if maintenance else "Unknown",
        "version_string": date_new,
        "title": maintenance["title"] if maintenance else "Unknown",
        "url": maintenance["url"] if maintenance else "Unknown",
    }


def get_patch_context():
    """
    Returns a dictionary containing:
    - retail_prev, date_prev: The latest registered version.
    - retail_new, date_new: The latest versions found externally.
    - is_new: True if date_new is not in the registry.
    """
    versions = load_versions()
    prev = versions[-1] if versions else None

    date_new = fetch_latest_thaliak_patch()

    maintenance = scrape_latest_maintenance()
    retail_new = maintenance["retail_version"] if maintenance else None

    is_new = False
    if date_new:
        is_new = not any(v["version_string"] == date_new for v in versions)

    return {
        "retail_prev": prev["retail_version"] if prev else None,
        "date_prev": prev["version_string"] if prev else None,
        "retail_new": retail_new,
        "date_new": date_new,
        "is_new": is_new,
    }


def update_and_get_info():
    """
    Discovers current patch context, prints results for GitHub Actions,
    and updates the local registration if a new version is found.
    """
    ctx = get_patch_context()

    if ctx["date_prev"]:
        print(f"date_prev={ctx['date_prev']}")
    if ctx["retail_prev"]:
        print(f"retail_prev={ctx['retail_prev']}")
    if ctx["date_new"]:
        print(f"date_new={ctx['date_new']}")
    if ctx["retail_new"]:
        print(f"retail_new={ctx['retail_new']}")
    print(f"is_new={'true' if ctx['is_new'] else 'false'}")

    if ctx["is_new"] and ctx["date_new"] and ctx["retail_new"]:
        data = load_versions()
        data.append(
            {"retail_version": ctx["retail_new"], "version_string": ctx["date_new"]}
        )
        print(
            f"Added new version mapping: {ctx['retail_new']} -> {ctx['date_new']}",
            file=sys.stderr,
        )
        with open(VERSIONS_FILE, "w") as f:
            json.dump(data, f, indent=2)


if __name__ == "__main__":
    update_and_get_info()
