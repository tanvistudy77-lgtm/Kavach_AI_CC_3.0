export type RiskLevel = "LOW" | "SUSPICIOUS" | "HIGH" | "CRITICAL";

export type SignalCategory =
  | "urgency"
  | "fear"
  | "credentials"
  | "financial"
  | "url"
  | "impersonation";

export interface ThreatSignal {
  id: string;
  label: string;
  points: number;
  reason: string;
  category: SignalCategory;
}

export interface AnalysisResult {
  score: number;
  level: RiskLevel;
  category: string;
  signals: ThreatSignal[];

  scamDNA: {
    urgency: number;
    fear: number;
    impersonation: number;
    credentials: number;
    urlRisk: number;
  };

  claimedBrand?: string;
  observedDomain?: string;
  expectedDomain?: string;
  trustGap?: number;

  deceptionChain: string[];
  actions: string[];
}

const brands = [
  {
    display: "State Bank of India",
    names: ["sbi", "state bank of india"],
    domains: ["sbi.co.in"],
  },
  {
    display: "HDFC Bank",
    names: ["hdfc", "hdfc bank"],
    domains: ["hdfcbank.com"],
  },
  {
    display: "ICICI Bank",
    names: ["icici", "icici bank"],
    domains: ["icicibank.com"],
  },
  {
    display: "Paytm",
    names: ["paytm"],
    domains: ["paytm.com"],
  },
  {
    display: "PhonePe",
    names: ["phonepe"],
    domains: ["phonepe.com"],
  },
  {
    display: "Amazon",
    names: ["amazon"],
    domains: ["amazon.in", "amazon.com"],
  },
  {
    display: "Flipkart",
    names: ["flipkart"],
    domains: ["flipkart.com"],
  },
];

function extractUrl(text: string): string | null {
  const match = text.match(/https?:\/\/[^\s]+|www\.[^\s]+/i);

  if (!match) return null;

  return match[0].replace(/[),.;!?]+$/, "");
}

function isTrustedDomain(hostname: string, allowedDomains: string[]) {
  return allowedDomains.some(
    (domain) =>
      hostname === domain || hostname.endsWith(`.${domain}`)
  );
}

export function analyzeThreat(rawInput: string): AnalysisResult {
  const input = rawInput.trim();
  const lower = input.toLowerCase();

  const signals: ThreatSignal[] = [];

  const addSignal = (
    id: string,
    label: string,
    points: number,
    reason: string,
    category: SignalCategory
  ) => {
    if (!signals.some((signal) => signal.id === id)) {
      signals.push({
        id,
        label,
        points,
        reason,
        category,
      });
    }
  };

  const urgencyDetected =
    /\b(urgent|urgently|immediately|right now|act now|today only|within \d+ hours?|expire|expires|last chance)\b/i.test(
      input
    );

  if (urgencyDetected) {
    addSignal(
      "urgency",
      "Artificial urgency",
      13,
      "The message pressures the user to act quickly.",
      "urgency"
    );
  }

  const fearDetected =
    /\b(blocked|block your|suspended|suspend|deactivated|deactivate|legal action|police|penalty|account closed|account will be blocked)\b/i.test(
      input
    );

  if (fearDetected) {
    addSignal(
      "fear",
      "Fear / pressure tactic",
      11,
      "The message threatens a negative consequence.",
      "fear"
    );
  }

  const credentialsDetected =
    /\b(otp|password|pin|cvv|kyc|login|log in|verify account|verify your account|bank details|card details|credentials)\b/i.test(
      input
    );

  if (credentialsDetected) {
    addSignal(
      "credentials",
      "Credential or identity request",
      24,
      "The message references sensitive authentication or account information.",
      "credentials"
    );
  }

  const financialDetected =
    /(₹|\brs\.?\s?\d|\bupi\b|cashback|lottery|prize|reward|refund|investment|guaranteed return|payment request|claim money)/i.test(
      input
    );

  if (financialDetected) {
    addSignal(
      "financial",
      "Financial lure",
      10,
      "Money, rewards, payments or financial incentives are used.",
      "financial"
    );
  }

  const detectedBrand = brands.find((brand) =>
    brand.names.some((name) => lower.includes(name))
  );

  const foundUrl = extractUrl(input);

  let observedDomain: string | undefined;
  let expectedDomain: string | undefined;
  let trustGap: number | undefined;

  if (foundUrl) {
    try {
      const normalizedUrl = foundUrl.startsWith("www.")
        ? `https://${foundUrl}`
        : foundUrl;

      const parsed = new URL(normalizedUrl);

      observedDomain = parsed.hostname.toLowerCase().replace(/^www\./, "");

      if (
        /bit\.ly|tinyurl\.com|t\.co|goo\.gl|rb\.gy|cutt\.ly|shorturl/i.test(
          observedDomain
        )
      ) {
        addSignal(
          "short-url",
          "Shortened URL",
          14,
          "Shortened links can hide the real destination.",
          "url"
        );
      }

      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(observedDomain)) {
        addSignal(
          "ip-domain",
          "IP address used as domain",
          15,
          "Legitimate consumer services rarely use raw IP addresses in messages.",
          "url"
        );
      }

      if (observedDomain.includes("xn--")) {
        addSignal(
          "punycode",
          "Punycode domain",
          16,
          "The domain may be using visually deceptive international characters.",
          "url"
        );
      }

      if (
        /\.(xyz|top|click|buzz|live|support|info|site|online)$/i.test(
          observedDomain
        )
      ) {
        addSignal(
          "risky-tld",
          "Suspicious domain ending",
          12,
          "The domain uses an ending frequently seen in disposable or deceptive links.",
          "url"
        );
      }

      if (
        /(secure|verify|verification|update|kyc|login|signin|account|support)/i.test(
          observedDomain
        )
      ) {
        addSignal(
          "lure-domain",
          "Trust-building words inside domain",
          12,
          "The domain uses words such as secure, verify or update to appear legitimate.",
          "url"
        );
      }

      if (observedDomain.split(".").length >= 4) {
        addSignal(
          "many-subdomains",
          "Excessive subdomains",
          8,
          "Long chains of subdomains can be used to disguise the real domain.",
          "url"
        );
      }
    } catch {
      addSignal(
        "invalid-url",
        "Malformed URL",
        15,
        "The detected link has an unusual or invalid structure.",
        "url"
      );
    }
  }

  if (detectedBrand && observedDomain) {
    expectedDomain = detectedBrand.domains[0];

    if (!isTrustedDomain(observedDomain, detectedBrand.domains)) {
      addSignal(
        "brand-mismatch",
        "Brand / domain mismatch",
        22,
        `${detectedBrand.display} is mentioned, but the link does not use its expected domain.`,
        "impersonation"
      );

      trustGap = 96;
    } else {
      trustGap = 8;
    }
  }

  let score = signals.reduce((total, signal) => total + signal.points, 0);
  score = Math.min(100, score);

  if (signals.length === 0) {
    score = 5;
  }

  let level: RiskLevel;

  if (score >= 80) level = "CRITICAL";
  else if (score >= 60) level = "HIGH";
  else if (score >= 30) level = "SUSPICIOUS";
  else level = "LOW";

  let category = "No major threat detected";

  const hasImpersonation = signals.some(
    (signal) => signal.category === "impersonation"
  );

  const hasUrlRisk = signals.some(
    (signal) => signal.category === "url"
  );

  if (hasImpersonation && credentialsDetected) {
    category = "Brand impersonation phishing";
  } else if (credentialsDetected && hasUrlRisk) {
    category = "Credential phishing";
  } else if (financialDetected && urgencyDetected) {
    category = "Financial / reward scam";
  } else if (hasUrlRisk) {
    category = "Suspicious link";
  } else if (score >= 30) {
    category = "Suspicious social-engineering message";
  }

  const urlPoints = signals
    .filter((signal) => signal.category === "url")
    .reduce((sum, signal) => sum + signal.points, 0);

  const scamDNA = {
    urgency: urgencyDetected ? 92 : 8,
    fear: fearDetected ? 84 : 7,
    impersonation: hasImpersonation ? 96 : detectedBrand ? 25 : 5,
    credentials: credentialsDetected ? 95 : 5,
    urlRisk: hasUrlRisk ? Math.min(98, 35 + urlPoints * 2) : foundUrl ? 15 : 5,
  };

  const deceptionChain: string[] = [];

  if (detectedBrand) {
    deceptionChain.push(`Claims trust using ${detectedBrand.display}`);
  }

  if (fearDetected) {
    deceptionChain.push("Creates fear of account loss or negative consequences");
  }

  if (urgencyDetected) {
    deceptionChain.push("Pressures the victim to act immediately");
  }

  if (observedDomain) {
    deceptionChain.push(`Redirects the user to ${observedDomain}`);
  }

  if (credentialsDetected) {
    deceptionChain.push("Attempts to obtain identity or authentication information");
  }

  if (financialDetected) {
    deceptionChain.push("Uses money, reward or payment pressure to influence action");
  }

  if (deceptionChain.length === 0) {
    deceptionChain.push(
      "No clear deception chain detected from the current signals"
    );
  }

  const actions =
    level === "LOW"
      ? [
          "No major suspicious indicators were detected.",
          "Still verify unexpected requests independently before acting.",
        ]
      : [
          "Do not open suspicious links from this message.",
          "Never share OTP, PIN, CVV or passwords.",
          "Open the organisation's official app or website manually.",
          "Contact the organisation through a trusted official channel if unsure.",
        ];

  return {
    score,
    level,
    category,
    signals,
    scamDNA,
    claimedBrand: detectedBrand?.display,
    observedDomain,
    expectedDomain,
    trustGap,
    deceptionChain,
    actions,
  };
}