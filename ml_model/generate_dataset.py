"""
Generate a diverse, realistic phishing URL dataset for training.
Produces ~2000 URLs (1000 legitimate + 1000 phishing) with varied patterns.
"""
import csv
import random
import itertools

random.seed(42)

# ─── Legitimate URL building blocks ───
LEGIT_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "netflix.com",
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com", "medium.com",
    "quora.com", "nytimes.com", "bbc.co.uk", "cnn.com", "reuters.com",
    "walmart.com", "ebay.com", "etsy.com", "target.com", "bestbuy.com",
    "adobe.com", "salesforce.com", "zoom.us", "slack.com", "dropbox.com",
    "spotify.com", "twitch.tv", "pinterest.com", "tumblr.com", "snapchat.com",
    "paypal.com", "stripe.com", "shopify.com", "squarespace.com", "wordpress.com",
    "cloudflare.com", "heroku.com", "digitalocean.com", "aws.amazon.com", "azure.microsoft.com",
    "docs.google.com", "drive.google.com", "mail.google.com", "maps.google.com", "play.google.com",
    "developer.mozilla.org", "w3schools.com", "freecodecamp.org", "coursera.org", "udemy.com",
    "khanacademy.org", "edx.org", "mit.edu", "stanford.edu", "harvard.edu",
    "nasa.gov", "nih.gov", "cdc.gov", "who.int", "un.org",
    "imdb.com", "rottentomatoes.com", "goodreads.com", "archive.org", "wikimedia.org",
    "figma.com", "canva.com", "notion.so", "trello.com", "asana.com",
    "gitlab.com", "bitbucket.org", "npmjs.com", "pypi.org", "hub.docker.com",
    "airbnb.com", "booking.com", "tripadvisor.com", "expedia.com", "kayak.com",
    "uber.com", "lyft.com", "doordash.com", "grubhub.com", "instacart.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com", "usbank.com",
]

LEGIT_PATHS = [
    "", "/", "/home", "/about", "/contact", "/login", "/signup", "/products",
    "/services", "/blog", "/news", "/help", "/support", "/faq", "/pricing",
    "/features", "/docs", "/api", "/dashboard", "/settings", "/account",
    "/search", "/explore", "/trending", "/popular", "/categories",
    "/en/docs/guide", "/articles/2026/latest", "/resources/download",
    "/community/forums", "/developers/reference",
]

LEGIT_QUERIES = [
    "", "?q=search+term", "?page=2", "?lang=en", "?ref=homepage",
    "?utm_source=google", "?id=12345", "?category=tech", "?sort=popular",
]

# ─── Phishing URL building blocks ───
BRAND_TYPOS = {
    "google": ["g00gle", "gooogle", "googie", "go0gle", "gogle", "googl3"],
    "paypal": ["paypa1", "paypai", "payp4l", "paypol", "paypall", "p4ypal"],
    "amazon": ["amaz0n", "amazom", "amzon", "anazon", "amazn", "4mazon"],
    "apple": ["app1e", "appie", "aple", "applle", "4pple"],
    "microsoft": ["micros0ft", "mircosoft", "micorsoft", "m1crosoft", "microsft"],
    "facebook": ["faceb00k", "facebok", "faecbook", "faceboook", "f4cebook"],
    "netflix": ["netf1ix", "netfiix", "netfliix", "n3tflix", "netlfix"],
    "instagram": ["instagr4m", "1nstagram", "instgram", "instagam", "lnstagram"],
    "linkedin": ["1inkedin", "linkedln", "l1nkedin", "linkdin", "linkediin"],
    "chase": ["chas3", "chace", "ch4se"],
    "wellsfargo": ["we11sfargo", "wellsfarg0", "welsfargo"],
    "bankofamerica": ["bankofamer1ca", "bank0famerica", "bankofamerca"],
}

PHISH_TLDS = [".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".club", ".work", ".buzz", ".icu", ".cam", ".rest"]
PHISH_KEYWORDS = ["login", "verify", "secure", "update", "confirm", "account", "signin",
                   "password", "billing", "suspend", "alert", "unusual", "restore", "unlock"]
PHISH_SUBDOMAINS = ["secure", "login", "verify", "account", "update", "auth", "signin",
                    "mail", "webmail", "portal", "app", "service", "support", "help"]

def generate_legit_urls(n=1000):
    urls = set()
    # Type 1: Simple domain URLs (with and without www)
    for domain in LEGIT_DOMAINS:
        urls.add(f"https://www.{domain}")
        urls.add(f"https://{domain}")

    # Type 2: Domain + path
    for domain in LEGIT_DOMAINS:
        for path in random.sample(LEGIT_PATHS, min(5, len(LEGIT_PATHS))):
            urls.add(f"https://{domain}{path}")

    # Type 3: Domain + path + query
    for _ in range(200):
        domain = random.choice(LEGIT_DOMAINS)
        path = random.choice(LEGIT_PATHS)
        query = random.choice(LEGIT_QUERIES)
        urls.add(f"https://{domain}{path}{query}")

    # Type 4: Subdomain variations
    for _ in range(100):
        domain = random.choice(LEGIT_DOMAINS)
        sub = random.choice(["www", "blog", "docs", "api", "dev", "app", "m", "cdn"])
        path = random.choice(LEGIT_PATHS[:10])
        urls.add(f"https://{sub}.{domain}{path}")

    result = list(urls)
    random.shuffle(result)
    return result[:n]

def generate_phish_urls(n=1000):
    urls = set()

    # Type 1: Typosquatting with free TLDs
    for brand, typos in BRAND_TYPOS.items():
        for typo in typos:
            tld = random.choice(PHISH_TLDS)
            kw = random.choice(PHISH_KEYWORDS)
            urls.add(f"http://{typo}-{kw}{tld}")
            urls.add(f"http://{typo}{tld}/{kw}")
            urls.add(f"https://{typo}-{kw}{tld}/auth")
            urls.add(f"http://{kw}-{typo}{tld}")

    # Type 2: Subdomain abuse (brand in subdomain, evil domain)
    for brand in BRAND_TYPOS.keys():
        for _ in range(8):
            sub = random.choice(PHISH_SUBDOMAINS)
            evil_domain = ''.join(random.choices("abcdefghijklmnop", k=random.randint(5, 10)))
            tld = random.choice(PHISH_TLDS)
            kw = random.choice(PHISH_KEYWORDS)
            urls.add(f"http://{sub}.{brand}.{evil_domain}{tld}/{kw}")
            urls.add(f"http://{brand}.{sub}.{evil_domain}{tld}")

    # Type 3: IP-based URLs
    for _ in range(60):
        ip = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        port = random.choice(["", ":8080", ":8443", ":3000", ":4443"])
        path = random.choice(["/login", "/verify", "/account", "/secure/auth", "/update/confirm", "/signin"])
        urls.add(f"http://{ip}{port}{path}")

    # Type 4: Long obfuscated URLs
    for _ in range(100):
        brand = random.choice(list(BRAND_TYPOS.keys()))
        evil = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(8, 15)))
        tld = random.choice(PHISH_TLDS)
        depth = "/".join(random.choices(PHISH_KEYWORDS, k=random.randint(3, 6)))
        query = f"?user={brand}&token={''.join(random.choices('abcdef0123456789', k=16))}"
        urls.add(f"http://{evil}{tld}/{depth}{query}")

    # Type 5: @ symbol trick
    for _ in range(40):
        real = random.choice(LEGIT_DOMAINS[:20])
        evil = ''.join(random.choices("abcdefghijklmnop", k=8))
        tld = random.choice(PHISH_TLDS)
        urls.add(f"http://{real}@{evil}{tld}/login")

    # Type 6: Hyphen-heavy domains
    for _ in range(80):
        parts = random.sample(PHISH_KEYWORDS, random.randint(2, 4))
        tld = random.choice(PHISH_TLDS)
        urls.add(f"http://{'-'.join(parts)}{tld}")
        urls.add(f"http://{'-'.join(parts)}-{''.join(random.choices('0123456789', k=3))}{tld}")

    # Type 7: Mixed HTTPS phishing (modern phishing uses HTTPS too)
    for _ in range(80):
        brand = random.choice(list(BRAND_TYPOS.keys()))
        typo = random.choice(BRAND_TYPOS[brand])
        kw = random.choice(PHISH_KEYWORDS)
        tld = random.choice(PHISH_TLDS + [".com", ".net", ".org"])
        urls.add(f"https://{typo}-{kw}{tld}/auth/verify")
        urls.add(f"https://{kw}.{typo}{tld}/secure")

    # Type 8: Excessive subdomains
    for _ in range(60):
        brand = random.choice(list(BRAND_TYPOS.keys()))
        subs = ".".join(random.sample(PHISH_SUBDOMAINS, random.randint(2, 4)))
        evil = ''.join(random.choices("abcdefghijklmnop", k=6))
        tld = random.choice(PHISH_TLDS)
        urls.add(f"http://{subs}.{brand}.{evil}{tld}")

    result = list(urls)
    random.shuffle(result)
    return result[:n]

def main():
    legit = generate_legit_urls(1000)
    phish = generate_phish_urls(1000)

    all_urls = [(url, 0) for url in legit] + [(url, 1) for url in phish]
    random.shuffle(all_urls)

    output_path = "ml_model/phishing_urls.csv"
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(all_urls)

    print(f"Generated {len(all_urls)} URLs ({len(legit)} legit + {len(phish)} phishing)")
    print(f"Saved to {output_path}")

if __name__ == "__main__":
    main()
