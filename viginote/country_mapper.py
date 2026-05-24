"""
country_mapper.py — VigiNote location to ISO country code mapping
Covers all monitored locations across 7 regions + maritime chokepoints.
Used by collector.py to tag every alert with a country code at ingest time.
"""
from __future__ import annotations
import re

# ── Region → countries master map ────────────────────────────────────────────
REGION_COUNTRIES: dict[str, list[str]] = {
    "GLOBAL": [],
    "MIDDLE_EAST": [
        "IL","PS","SY","IQ","IR","YE","LB","JO","SA","AE",
        "KW","QA","BH","OM","TR","KZ","UZ","TM","GE",
    ],
    "EUROPE": [
        "UA","RU","BY","MD","GE","AM","AZ","RS","XK","BA",
        "MK","AL","ME","HR","SI","SK","CZ","PL","HU","RO",
        "BG","GR","TR","LT","LV","EE","FI","NO","SE","DE",
        "FR","GB","IT","ES","PT","NL","BE","AT","CH",
    ],
    "ASIA": [
        "CN","TW","HK","KP","KR","JP","MM","TH","PH","VN",
        "KH","LA","MY","SG","ID","AF","PK","IN","BD","LK",
        "NP","BT","MN","TJ","KG","UZ","TM","PG","FJ","SB",
    ],
    "WEST_EAST_AFRICA": [
        "SD","SS","ET","SO","NG","ML","BF","NE","TD","CF",
        "CD","KE","UG","TZ","RW","BI","DJ","ER","GH","SN",
        "GN","SL","LR","CI","CM","GA","CG","MR","GM","TG","BJ",
    ],
    "SOUTHERN_AFRICA": [
        "ZA","ZW","MZ","ZM","MW","NA","BW","AO","LS","SZ",
        "MG","MU","SC","KM","RE",
    ],
    "SOUTH_AMERICA": [
        "VE","CO","BR","MX","HT","PE","EC","BO","AR","CL",
        "PY","UY","GY","SR","GT","HN","SV","NI","CR","PA",
        "CU","JM","TT","DO",
    ],
}

# ── Country ISO → full name ───────────────────────────────────────────────────
COUNTRY_NAMES: dict[str, str] = {
    "IL":"Israel","PS":"Palestine","SY":"Syria","IQ":"Iraq","IR":"Iran",
    "YE":"Yemen","LB":"Lebanon","JO":"Jordan","SA":"Saudi Arabia","AE":"UAE",
    "KW":"Kuwait","QA":"Qatar","BH":"Bahrain","OM":"Oman","TR":"Turkey",
    "UA":"Ukraine","RU":"Russia","BY":"Belarus","MD":"Moldova","GE":"Georgia",
    "AM":"Armenia","AZ":"Azerbaijan","RS":"Serbia","XK":"Kosovo","BA":"Bosnia",
    "MK":"North Macedonia","AL":"Albania","ME":"Montenegro","PL":"Poland",
    "HU":"Hungary","RO":"Romania","BG":"Bulgaria","GR":"Greece","GB":"UK",
    "DE":"Germany","FR":"France","IT":"Italy","ES":"Spain",
    "CN":"China","TW":"Taiwan","HK":"Hong Kong","KP":"North Korea",
    "KR":"South Korea","JP":"Japan","MM":"Myanmar","TH":"Thailand",
    "PH":"Philippines","VN":"Vietnam","AF":"Afghanistan","PK":"Pakistan",
    "IN":"India","BD":"Bangladesh","LK":"Sri Lanka","ID":"Indonesia",
    "MY":"Malaysia","SG":"Singapore","KH":"Cambodia","LA":"Laos",
    "MN":"Mongolia","PG":"Papua New Guinea",
    "SD":"Sudan","SS":"South Sudan","ET":"Ethiopia","SO":"Somalia",
    "NG":"Nigeria","ML":"Mali","BF":"Burkina Faso","NE":"Niger",
    "TD":"Chad","CF":"Central African Republic","CD":"DR Congo",
    "KE":"Kenya","UG":"Uganda","TZ":"Tanzania","RW":"Rwanda",
    "BI":"Burundi","DJ":"Djibouti","ER":"Eritrea","GH":"Ghana",
    "SN":"Senegal","CI":"Côte d'Ivoire","CM":"Cameroon","MR":"Mauritania",
    "ZA":"South Africa","ZW":"Zimbabwe","MZ":"Mozambique","ZM":"Zambia",
    "MW":"Malawi","NA":"Namibia","BW":"Botswana","AO":"Angola",
    "LS":"Lesotho","SZ":"Eswatini","MG":"Madagascar",
    "VE":"Venezuela","CO":"Colombia","BR":"Brazil","MX":"Mexico",
    "HT":"Haiti","PE":"Peru","EC":"Ecuador","BO":"Bolivia",
    "AR":"Argentina","CL":"Chile","PY":"Paraguay","UY":"Uruguay",
    "GT":"Guatemala","HN":"Honduras","SV":"El Salvador","NI":"Nicaragua",
    "CU":"Cuba","DO":"Dominican Republic","JM":"Jamaica","TT":"Trinidad",
}

# ── Location string → ISO country code ───────────────────────────────────────
# Ordered longest match first to avoid partial matches
_RAW_MAP: list[tuple[str, str]] = [
    # Palestine / Gaza — before Israel to avoid partial match
    ("west bank", "PS"), ("gaza strip", "PS"), ("khan younis", "PS"),
    ("khan yunis", "PS"), ("rafah", "PS"), ("jabalia", "PS"),
    ("beit lahiya", "PS"), ("beit hanoun", "PS"), ("deir al-balah", "PS"),
    ("nuseirat", "PS"), ("ramallah", "PS"), ("jenin", "PS"),
    ("nablus", "PS"), ("tulkarm", "PS"), ("hebron", "PS"),
    ("jericho", "PS"), ("bethlehem", "PS"), ("gaza", "PS"),
    ("palestine", "PS"), ("palestinian", "PS"),
    # Israel
    ("tel aviv", "IL"), ("jerusalem", "IL"), ("haifa", "IL"),
    ("beer sheva", "IL"), ("netanya", "IL"), ("rishon lezion", "IL"),
    ("ashdod", "IL"), ("petah tikva", "IL"), ("nahariya", "IL"),
    ("sderot", "IL"), ("ashkelon", "IL"), ("eilat", "IL"),
    ("golan heights", "IL"), ("israel", "IL"), ("israeli", "IL"),
    ("idf", "IL"),
    # Syria
    ("damascus", "SY"), ("aleppo", "SY"), ("homs", "SY"),
    ("idlib", "SY"), ("deir ez-zor", "SY"), ("raqqa", "SY"),
    ("hasaka", "SY"), ("latakia", "SY"), ("daraa", "SY"),
    ("syria", "SY"), ("syrian", "SY"),
    # Iraq
    ("baghdad", "IQ"), ("mosul", "IQ"), ("basra", "IQ"),
    ("erbil", "IQ"), ("kirkuk", "IQ"), ("fallujah", "IQ"),
    ("najaf", "IQ"), ("karbala", "IQ"), ("tikrit", "IQ"),
    ("iraq", "IQ"), ("iraqi", "IQ"),
    # Iran
    ("tehran", "IR"), ("isfahan", "IR"), ("mashhad", "IR"),
    ("tabriz", "IR"), ("shiraz", "IR"), ("ahvaz", "IR"),
    ("qom", "IR"), ("bandar abbas", "IR"), ("zahedan", "IR"),
    ("iran", "IR"), ("iranian", "IR"), ("irgc", "IR"),
    ("revolutionary guard", "IR"), ("quds force", "IR"),
    # Yemen
    ("sanaa", "YE"), ("sana'a", "YE"), ("aden", "YE"),
    ("hudaydah", "YE"), ("hodeidah", "YE"), ("marib", "YE"),
    ("taiz", "YE"), ("mukalla", "YE"), ("saada", "YE"),
    ("yemen", "YE"), ("yemeni", "YE"), ("houthi", "YE"),
    ("ansar allah", "YE"),
    # Lebanon
    ("beirut", "LB"), ("tripoli", "LB"), ("sidon", "LB"),
    ("tyre", "LB"), ("baalbek", "LB"), ("south lebanon", "LB"),
    ("lebanon", "LB"), ("lebanese", "LB"), ("hezbollah", "LB"),
    # Jordan
    ("amman", "JO"), ("zarqa", "JO"), ("irbid", "JO"),
    ("jordan", "JO"), ("jordanian", "JO"),
    # Saudi Arabia
    ("riyadh", "SA"), ("jeddah", "SA"), ("mecca", "SA"),
    ("medina", "SA"), ("dhahran", "SA"), ("saudi arabia", "SA"),
    ("saudi", "SA"), ("aramco", "SA"),
    # UAE
    ("dubai", "AE"), ("abu dhabi", "AE"), ("sharjah", "AE"),
    ("uae", "AE"), ("emirates", "AE"),
    # Turkey
    ("ankara", "TR"), ("istanbul", "TR"), ("izmir", "TR"),
    ("gaziantep", "TR"), ("diyarbakir", "TR"), ("turkey", "TR"),
    ("turkish", "TR"), ("erdogan", "TR"),
    # Ukraine
    ("kyiv", "UA"), ("kharkiv", "UA"), ("mariupol", "UA"),
    ("zaporizhzhia", "UA"), ("odesa", "UA"), ("odessa", "UA"),
    ("lviv", "UA"), ("dnipro", "UA"), ("donetsk", "UA"),
    ("luhansk", "UA"), ("kherson", "UA"), ("mykolaiv", "UA"),
    ("bakhmut", "UA"), ("avdiivka", "UA"), ("kramatorsk", "UA"),
    ("ukraine", "UA"), ("ukrainian", "UA"), ("zelensky", "UA"),
    ("zelenskyy", "UA"),
    # Russia
    ("moscow", "RU"), ("st petersburg", "RU"), ("saint petersburg", "RU"),
    ("novosibirsk", "RU"), ("yekaterinburg", "RU"), ("kazan", "RU"),
    ("rostov", "RU"), ("belgorod", "RU"), ("kursk", "RU"),
    ("russia", "RU"), ("russian", "RU"), ("kremlin", "RU"),
    ("putin", "RU"), ("wagner", "RU"), ("fsb", "RU"), ("gru", "RU"),
    # Belarus
    ("minsk", "BY"), ("belarus", "BY"), ("belarusian", "BY"),
    ("lukashenko", "BY"),
    # Georgia
    ("tbilisi", "GE"), ("batumi", "GE"), ("south ossetia", "GE"),
    ("abkhazia", "GE"), ("georgia", "GE"),
    # Armenia / Azerbaijan
    ("yerevan", "AM"), ("armenia", "AM"), ("armenian", "AM"),
    ("baku", "AZ"), ("nagorno-karabakh", "AZ"), ("karabakh", "AZ"),
    ("azerbaijan", "AZ"), ("azerbaijani", "AZ"),
    # Balkans
    ("belgrade", "RS"), ("serbia", "RS"), ("serbian", "RS"),
    ("pristina", "XK"), ("kosovo", "XK"),
    ("sarajevo", "BA"), ("bosnia", "BA"),
    ("skopje", "MK"), ("north macedonia", "MK"),
    ("tirana", "AL"), ("albania", "AL"),
    # China / Taiwan
    ("beijing", "CN"), ("shanghai", "CN"), ("hong kong", "HK"),
    ("guangzhou", "CN"), ("shenzhen", "CN"), ("xinjiang", "CN"),
    ("tibet", "CN"), ("uyghur", "CN"), ("taiwan strait", "TW"),
    ("taipei", "TW"), ("taiwan", "TW"), ("china", "CN"),
    ("chinese", "CN"), ("pla", "CN"), ("ccp", "CN"),
    # North / South Korea
    ("pyongyang", "KP"), ("north korea", "KP"), ("dprk", "KP"),
    ("kim jong", "KP"), ("seoul", "KR"), ("south korea", "KR"),
    # Japan
    ("tokyo", "JP"), ("osaka", "JP"), ("japan", "JP"), ("japanese", "JP"),
    # Myanmar
    ("naypyidaw", "MM"), ("yangon", "MM"), ("mandalay", "MM"),
    ("myanmar", "MM"), ("burma", "MM"), ("tatmadaw", "MM"),
    ("rohingya", "MM"),
    # Afghanistan
    ("kabul", "AF"), ("kandahar", "AF"), ("herat", "AF"),
    ("jalalabad", "AF"), ("mazar-i-sharif", "AF"),
    ("afghanistan", "AF"), ("afghan", "AF"), ("taliban", "AF"),
    # Pakistan
    ("islamabad", "PK"), ("karachi", "PK"), ("lahore", "PK"),
    ("peshawar", "PK"), ("quetta", "PK"), ("rawalpindi", "PK"),
    ("khyber", "PK"), ("balochistan", "PK"), ("pakistan", "PK"),
    ("pakistani", "PK"), ("isi", "PK"),
    # India
    ("new delhi", "IN"), ("mumbai", "IN"), ("kolkata", "IN"),
    ("chennai", "IN"), ("bangalore", "IN"), ("kashmir", "IN"),
    ("manipur", "IN"), ("india", "IN"), ("indian", "IN"),
    # SE Asia
    ("bangkok", "TH"), ("thailand", "TH"), ("thai", "TH"),
    ("manila", "PH"), ("philippines", "PH"), ("philippine", "PH"),
    ("hanoi", "VN"), ("ho chi minh", "VN"), ("vietnam", "VN"),
    ("phnom penh", "KH"), ("cambodia", "KH"),
    ("vientiane", "LA"), ("laos", "LA"),
    ("kuala lumpur", "MY"), ("malaysia", "MY"),
    ("jakarta", "ID"), ("indonesia", "ID"), ("papua", "ID"),
    ("singapore", "SG"),
    # Sudan / South Sudan
    ("khartoum", "SD"), ("omdurman", "SD"), ("port sudan", "SD"),
    ("darfur", "SD"), ("juba", "SS"), ("malakal", "SS"),
    ("wau", "SS"), ("sudan", "SD"), ("sudanese", "SD"),
    ("rsf", "SD"), ("saf ", "SD"), ("south sudan", "SS"),
    # Ethiopia
    ("addis ababa", "ET"), ("tigray", "ET"), ("amhara", "ET"),
    ("oromia", "ET"), ("mekelle", "ET"), ("gondar", "ET"),
    ("ethiopia", "ET"), ("ethiopian", "ET"), ("tplf", "ET"),
    ("olf", "ET"),
    # Somalia
    ("mogadishu", "SO"), ("hargeisa", "SO"), ("garowe", "SO"),
    ("kismayo", "SO"), ("baidoa", "SO"), ("somalia", "SO"),
    ("somali", "SO"), ("al-shabaab", "SO"), ("shabaab", "SO"),
    ("puntland", "SO"), ("somaliland", "SO"),
    # Nigeria
    ("abuja", "NG"), ("lagos", "NG"), ("kano", "NG"),
    ("kaduna", "NG"), ("maiduguri", "NG"), ("port harcourt", "NG"),
    ("borno", "NG"), ("niger delta", "NG"), ("biafra", "NG"),
    ("nigeria", "NG"), ("nigerian", "NG"), ("boko haram", "NG"),
    ("iswap", "NG"),
    # Sahel
    ("bamako", "ML"), ("mali", "ML"), ("malian", "ML"),
    ("ouagadougou", "BF"), ("burkina faso", "BF"), ("burkinabe", "BF"),
    ("niamey", "NE"), ("niger", "NE"), ("nigerien", "NE"),
    ("ndjamena", "TD"), ("chad", "TD"), ("chadian", "TD"),
    ("bangui", "CF"), ("central african republic", "CF"), ("car ", "CF"),
    ("jnim", "ML"), ("gsim", "ML"), ("aqim", "ML"),
    # DRC
    ("kinshasa", "CD"), ("goma", "CD"), ("bukavu", "CD"),
    ("beni", "CD"), ("butembo", "CD"), ("congo", "CD"),
    ("drc", "CD"), ("m23", "CD"), ("adf", "CD"),
    # East Africa
    ("nairobi", "KE"), ("mombasa", "KE"), ("kenya", "KE"),
    ("kampala", "UG"), ("uganda", "UG"),
    ("dar es salaam", "TZ"), ("dodoma", "TZ"), ("tanzania", "TZ"),
    ("kigali", "RW"), ("rwanda", "RW"),
    ("bujumbura", "BI"), ("burundi", "BI"),
    ("djibouti", "DJ"), ("asmara", "ER"), ("eritrea", "ER"),
    # West Africa
    ("accra", "GH"), ("ghana", "GH"),
    ("dakar", "SN"), ("senegal", "SN"),
    ("abidjan", "CI"), ("ivory coast", "CI"), ("cote d'ivoire", "CI"),
    ("yaounde", "CM"), ("douala", "CM"), ("cameroon", "CM"),
    ("libreville", "GA"), ("gabon", "GA"),
    ("nouakchott", "MR"), ("mauritania", "MR"),
    # Southern Africa
    ("johannesburg", "ZA"), ("cape town", "ZA"), ("durban", "ZA"),
    ("pretoria", "ZA"), ("south africa", "ZA"),
    ("harare", "ZW"), ("bulawayo", "ZW"), ("zimbabwe", "ZW"),
    ("maputo", "MZ"), ("beira", "MZ"), ("cabo delgado", "MZ"),
    ("mozambique", "MZ"), ("mozambican", "MZ"),
    ("lusaka", "ZM"), ("zambia", "ZM"),
    ("lilongwe", "MW"), ("blantyre", "MW"), ("malawi", "MW"),
    ("windhoek", "NA"), ("namibia", "NA"),
    ("gaborone", "BW"), ("botswana", "BW"),
    ("luanda", "AO"), ("angola", "AO"),
    # South America
    ("caracas", "VE"), ("maracaibo", "VE"), ("venezuela", "VE"),
    ("venezuelan", "VE"), ("maduro", "VE"), ("chavez", "VE"),
    ("bogota", "CO"), ("medellin", "CO"), ("cali", "CO"),
    ("colombia", "CO"), ("colombian", "CO"), ("farc", "CO"),
    ("eln", "CO"), ("gulf clan", "CO"),
    ("brasilia", "BR"), ("sao paulo", "BR"), ("rio de janeiro", "BR"),
    ("brazil", "BR"), ("brazilian", "BR"),
    ("mexico city", "MX"), ("guadalajara", "MX"), ("monterrey", "MX"),
    ("tijuana", "MX"), ("mexico", "MX"), ("mexican", "MX"),
    ("sinaloa", "MX"), ("jalisco", "MX"), ("cjng", "MX"),
    ("port-au-prince", "HT"), ("haiti", "HT"), ("haitian", "HT"),
    ("lima", "PE"), ("peru", "PE"),
    ("quito", "EC"), ("guayaquil", "EC"), ("ecuador", "EC"),
    ("la paz", "BO"), ("bolivia", "BO"),
    ("buenos aires", "AR"), ("argentina", "AR"),
    ("santiago", "CL"), ("chile", "CL"),
    ("asuncion", "PY"), ("paraguay", "PY"),
    ("havana", "CU"), ("cuba", "CU"), ("cuban", "CU"),
    ("santo domingo", "DO"), ("dominican republic", "DO"),
    ("kingston", "JM"), ("jamaica", "JM"),
    ("port of spain", "TT"), ("trinidad", "TT"),
    # Maritime / chokepoints — tag to nearest country
    ("red sea", "YE"), ("bab el-mandeb", "YE"), ("bab-el-mandeb", "YE"),
    ("gulf of aden", "SO"), ("somalia coast", "SO"),
    ("strait of hormuz", "IR"), ("hormuz", "IR"),
    ("persian gulf", "IR"), ("arabian sea", "PK"),
    ("strait of malacca", "MY"), ("malacca strait", "MY"),
    ("south china sea", "CN"), ("taiwan strait", "TW"),
    ("suez canal", "EG"), ("suez", "EG"),
]

# Pre-process: sort longest first, compile patterns
_LOCATION_MAP: list[tuple[re.Pattern, str]] = []

def _build_map():
    global _LOCATION_MAP
    sorted_entries = sorted(_RAW_MAP, key=lambda x: -len(x[0]))
    _LOCATION_MAP = [
        (re.compile(r'\b' + re.escape(loc) + r'\b', re.IGNORECASE), code)
        for loc, code in sorted_entries
    ]

_build_map()


def detect_country(locations: list[str], title: str = "", text: str = "") -> str | None:
    """
    Detect the primary country for an alert.
    Returns ISO 2-letter country code or None.
    Checks extracted locations first, then title, then article text.
    """
    # Build search corpus — locations are most reliable
    corpus_parts = [loc.lower() for loc in (locations or [])]
    if title:
        corpus_parts.append(title.lower())
    if text:
        corpus_parts.append(text[:500].lower())  # First 500 chars of article

    corpus = " . ".join(corpus_parts)
    if not corpus.strip():
        return None

    # Score each country match — first match wins (sorted longest first)
    for pattern, code in _LOCATION_MAP:
        if pattern.search(corpus):
            return code
    return None


def country_to_name(code: str) -> str:
    """Return full country name for an ISO code."""
    return COUNTRY_NAMES.get(code, code)


def country_to_region(code: str) -> str | None:
    """Return the VigiNote region for a country code."""
    for region, countries in REGION_COUNTRIES.items():
        if code in countries:
            return region
    return None


def countries_for_region(region: str) -> list[str]:
    """Return all country codes monitored in a region."""
    return REGION_COUNTRIES.get(region.upper(), [])


def all_monitored_countries() -> list[str]:
    """Return flat list of all monitored country codes."""
    codes = []
    for countries in REGION_COUNTRIES.values():
        codes.extend(countries)
    return list(set(codes))
