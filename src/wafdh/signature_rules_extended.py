from __future__ import annotations

from wafdh.models import Confidence
from wafdh.signature_types import WafRule

BUILTIN_EXTENDED_RULES: tuple[WafRule, ...] = (
    WafRule(
        "WatchGuard Fireware",
        "WatchGuard Technologies",
        Confidence.HIGH,
        header_patterns=(r"server:\s*watchguard",),
        body_patterns=(
            r"request denied by watchguard firewall",
            r"watchguard technologies inc\.",
            r"fireware xtm user authentication",
        ),
    ),
    WafRule(
        "Sucuri Website Firewall",
        "Sucuri",
        Confidence.HIGH,
        header_patterns=(
            r"x-sucuri-id:",
            r"x-sucuri-cache:",
            r"x-sucuri-block:",
            r"server:\s*sucuri",
        ),
        body_patterns=(
            r"access denied.{0,20}?sucuri website firewall",
            r"sucuri website firewall.{0,20}?access denied",
            r"cdn\.sucuri\.net/sucuri[-_]firewall[-_]block\.css",
            r"cloudproxy@sucuri\.net",
        ),
    ),
    WafRule(
        "Huawei Cloud WAF",
        "Huawei",
        Confidence.HIGH,
        header_patterns=(r"server:\s*huaweicloudwaf",),
        cookie_patterns=(r"^hwwafsesid=", r"^hwwafsestime="),
        body_patterns=(r"content=\"cloudwaf\"", r"hwclouds\.com", r"hws_security@"),
    ),
    WafRule(
        "SafeLine",
        "Chaitin Tech",
        Confidence.HIGH,
        body_patterns=(r"safeline", r"<!--\s*event id:"),
    ),
    WafRule(
        "Datadog App and API Protection",
        "Datadog",
        Confidence.HIGH,
        required_patterns=(r"security provided by datadog", r"security_response_id"),
    ),
    WafRule(
        "open-appsec",
        "Check Point",
        Confidence.HIGH,
        required_patterns=(
            r"x-request-id:\s*[0-9a-f]{32}",
            r"forbidden - id:\s*[0-9a-f]{32}",
        ),
    ),
    WafRule(
        "DealerOn Shield",
        "DealerOn",
        Confidence.MEDIUM,
        header_patterns=(r"x-dealeron-backend:.*shield_",),
    ),
    WafRule(
        "MOVEC WAF",
        "MOVEC",
        Confidence.HIGH,
        required_patterns=(r"waf\.movec\.services", r"\bblocked\b|access denied|forbidden"),
    ),
    WafRule(
        "PerimeterX",
        "PerimeterX",
        Confidence.HIGH,
        body_patterns=(
            r"www\.perimeterx\.(com|net)/whywasiblocked",
            r"client\.perimeterx\.(net|com)",
            r"denied because we believe you are using automation tools",
            r"access to this page has been denied because we believe you are using automation",
        ),
    ),
    WafRule(
        "Barracuda WAF",
        "Barracuda Networks",
        Confidence.HIGH,
        cookie_patterns=(
            r"^barra_counter_session=",
            r"^bni__barracuda_lb_cookie=",
            r"^bni_persistence=",
            r"^bn[ies]_.*?=",
        ),
        body_patterns=(r"barracuda\.networks",),
    ),
    WafRule(
        "Radware AppWall",
        "Radware",
        Confidence.HIGH,
        header_patterns=(r"x-sl-compstate:",),
        required_patterns=(
            (
                r"because we have detected unauthorized activity|"
                r"unauthorized activity has been detected"
            ),
            r"case number|security page",
        ),
        body_patterns=(r"cloudwebsec\.radware\.com",),
    ),
    WafRule(
        "Reblaze",
        "Reblaze",
        Confidence.HIGH,
        header_patterns=(r"server:\s*reblaze secure web gateway",),
        cookie_patterns=(r"^rbzid",),
        required_patterns=(
            r"current session has been terminated",
            r"access denied \(\d{3}\)|do not hesitate to contact us",
        ),
    ),
    WafRule(
        "Distil",
        "Distil Networks",
        Confidence.HIGH,
        body_patterns=(
            r"cdn\.distilnetworks\.com/images/anomaly\.detected\.png",
            r"distilcaptchaform",
            r"distilcallbackguard",
        ),
    ),
    WafRule(
        "NAXSI",
        "NBS Systems",
        Confidence.HIGH,
        header_patterns=(r"x-data-origin:\s*naxsi", r"server:\s*naxsi"),
        body_patterns=(r"blocked by naxsi", r"naxsi blocked information"),
    ),
    WafRule(
        "Zscaler",
        "Zscaler",
        Confidence.HIGH,
        header_patterns=(r"server:\s*zscaler",),
        body_patterns=(
            r"login\.zscloud\.net/img_logo_new1\.png",
            r"zscaler to protect you from internet threats",
            r"internet security by zscaler",
        ),
    ),
    WafRule(
        "StackPath",
        "StackPath",
        Confidence.HIGH,
        required_patterns=(
            r"using a security service for protection against online attacks",
            r"an action has triggered the service and blocked your request",
        ),
        body_patterns=(r"<title>stackpath[^<]+</title>", r"protected by .*stackpath\.com"),
    ),
    WafRule(
        "BitNinja",
        "BitNinja",
        Confidence.HIGH,
        body_patterns=(r"security check by bitninja", r"visitor anti-robot validation"),
    ),
    WafRule(
        "SonicWall",
        "SonicWall",
        Confidence.HIGH,
        header_patterns=(r"server:\s*sonicwall",),
        body_patterns=(r"<(title|h\d{1})>web site blocked", r"\+?nsa_banner"),
    ),
    WafRule(
        "Palo Alto Next Generation Firewall",
        "Palo Alto Networks",
        Confidence.HIGH,
        body_patterns=(
            r"download of virus\.spyware blocked",
            r"palo alto next generation security platform",
        ),
    ),
    WafRule(
        "MalCare",
        "Inactiv",
        Confidence.HIGH,
        body_patterns=(
            r"firewall.{0,15}?powered.by.{0,15}?malcare.{0,15}?pro",
            r"blocked because of malicious activities",
        ),
    ),
    WafRule(
        "SecuPress",
        "SecuPress",
        Confidence.HIGH,
        body_patterns=(r"<(title|h\d{1})>secupress",),
    ),
    WafRule(
        "Safe3 Web Firewall",
        "Safe3",
        Confidence.HIGH,
        header_patterns=(r"server:\s*safe3 web firewall", r"x-powered-by:\s*safe3waf/[.0-9]+"),
        body_patterns=(r"safe3waf/[0-9.]+",),
    ),
    WafRule(
        "Safedog",
        "SafeDog",
        Confidence.HIGH,
        header_patterns=(r"server:\s*safedog", r"x-safe-firewall:", r"safedog-flow"),
        cookie_patterns=(r"^safedog-flow-item=",),
        body_patterns=(r"safedogsite/broswer_logo\.jpg", r"404\.safedog\.cn"),
    ),
    WafRule(
        "Wallarm",
        "Wallarm",
        Confidence.HIGH,
        header_patterns=(r"server:\s*nginx[-_]wallarm",),
    ),
    WafRule(
        "GoDaddy Website Protection",
        "GoDaddy",
        Confidence.HIGH,
        body_patterns=(r"godaddy (security|website firewall)", r"seal\.godaddy\.com"),
    ),
    WafRule(
        "Shieldon Firewall",
        "Shieldon.io",
        Confidence.HIGH,
        header_patterns=(r"x-protected-by:\s*shieldon\.io",),
        required_patterns=(
            r"shieldon_captcha|status-user-info",
            r"access denied|please solve captcha",
        ),
    ),
    WafRule(
        "XLabs Security WAF",
        "XLabs",
        Confidence.HIGH,
        header_patterns=(
            r"x-cdn:\s*xlabs security",
            r"secured:\s*by xlabs security",
            r"server:\s*xlabs[-_]?.?waf",
        ),
    ),
    WafRule(
        "TransIP Web Firewall",
        "TransIP",
        Confidence.MEDIUM,
        header_patterns=(r"x-transip-backend:", r"x-transip-balancer:"),
    ),
)
