let currentUrl = "";

// --------------------------------------------------
// TRUSTED BRAND DIRECTORY
// --------------------------------------------------

const brands = [
  {
    name: "State Bank of India",
    words: ["sbi", "state bank of india"],
    domain: "sbi.co.in",
  },
  {
    name: "Paytm",
    words: ["paytm"],
    domain: "paytm.com",
  },
  {
    name: "HDFC Bank",
    words: ["hdfc", "hdfc bank"],
    domain: "hdfcbank.com",
  },
  {
    name: "ICICI Bank",
    words: ["icici", "icici bank"],
    domain: "icicibank.com",
  },
  {
    name: "PhonePe",
    words: ["phonepe"],
    domain: "phonepe.com",
  },
  {
    name: "Amazon",
    words: ["amazon"],
    domain: "amazon.in",
  },
  {
    name: "Flipkart",
    words: ["flipkart"],
    domain: "flipkart.com",
  },
];


// --------------------------------------------------
// HELPER FUNCTIONS
// --------------------------------------------------

function addSignal(signals, label, points, reason) {
  signals.push({
    label,
    points,
    reason,
  });
}


function extractUrl(text) {
  // Full URL
  const fullUrlMatch = text.match(/https?:\/\/[^\s]+/i);

  if (fullUrlMatch) {
    return fullUrlMatch[0].replace(/[),.;!?]+$/, "");
  }

  // Plain domain such as example.com
  const domainMatch = text
    .trim()
    .match(/^(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i);

  if (domainMatch) {
    return `https://${domainMatch[0]}`;
  }

  return null;
}


// --------------------------------------------------
// KAVACH LOCAL ANALYSIS ENGINE
// --------------------------------------------------

function analyze(input) {
  const text = input.toLowerCase();
  const signals = [];

  // -------------------------
  // URGENCY
  // -------------------------

  if (
    /\b(urgent|urgently|immediately|act now|today only|last chance|verify now|within \d+ hours?|expires?|limited time)\b/i.test(
      input
    )
  ) {
    addSignal(
      signals,
      "Artificial urgency",
      13,
      "The message pressures the user to act quickly."
    );
  }


  // -------------------------
  // FEAR / PRESSURE
  // -------------------------

  if (
    /\b(blocked|will be blocked|suspended|deactivated|legal action|police|penalty|account closed|account locked|service disconnected)\b/i.test(
      input
    )
  ) {
    addSignal(
      signals,
      "Fear pressure",
      11,
      "The message threatens a negative consequence."
    );
  }


  // -------------------------
  // CREDENTIAL REQUEST
  // -------------------------

  if (
    /\b(otp|password|pin|cvv|kyc|login|log in|bank details|card details|verify account|verify your account|credentials)\b/i.test(
      input
    )
  ) {
    addSignal(
      signals,
      "Credential request",
      24,
      "The message references sensitive authentication or account information."
    );
  }


  // -------------------------
  // FINANCIAL BAIT
  // -------------------------

  if (
    /(₹|\brs\.?\s?\d|cashback|lottery|reward|prize|refund|upi|investment|guaranteed return|claim money|free money)/i.test(
      input
    )
  ) {
    addSignal(
      signals,
      "Financial lure",
      10,
      "Money, rewards or payment incentives are being used to influence the user."
    );
  }


  // -------------------------
  // BRAND DETECTION
  // -------------------------

  const detectedBrand = brands.find((brand) =>
    brand.words.some((word) => text.includes(word))
  );


  // -------------------------
  // URL ANALYSIS
  // -------------------------

  const foundUrl = extractUrl(input);

  let hostname = "";

  if (foundUrl) {
    try {
      const parsedUrl = new URL(foundUrl);

      hostname = parsedUrl.hostname
        .toLowerCase()
        .replace(/^www\./, "");


      // Suspicious TLD
      if (
        /\.(xyz|top|click|buzz|site|online|live|support|info)$/i.test(
          hostname
        )
      ) {
        addSignal(
          signals,
          "Suspicious domain ending",
          12,
          "The URL uses a domain ending frequently seen in disposable or deceptive links."
        );
      }


      // Trust-building words
      if (
        /(secure|verify|verification|update|kyc|login|signin|account|support)/i.test(
          hostname
        )
      ) {
        addSignal(
          signals,
          "Trust-building domain words",
          12,
          "The domain uses words such as secure, verify or update to appear trustworthy."
        );
      }


      // Short URL
      if (
        /^(bit\.ly|tinyurl\.com|rb\.gy|cutt\.ly|t\.co|goo\.gl)$/i.test(
          hostname
        )
      ) {
        addSignal(
          signals,
          "Shortened URL",
          14,
          "The real destination may be hidden behind a shortened link."
        );
      }


      // Raw IP
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
        addSignal(
          signals,
          "IP address used instead of domain",
          15,
          "A raw IP address is unusual for trusted consumer services."
        );
      }


      // Punycode
      if (hostname.includes("xn--")) {
        addSignal(
          signals,
          "Possible look-alike domain",
          16,
          "The URL uses encoded characters that may imitate a trusted domain."
        );
      }


      // Excessive subdomains
      if (hostname.split(".").length >= 4) {
        addSignal(
          signals,
          "Excessive subdomains",
          8,
          "Multiple subdomains may be used to hide the real destination."
        );
      }

    } catch {
      addSignal(
        signals,
        "Malformed URL",
        15,
        "The link structure appears unusual or invalid."
      );
    }
  }


  // -------------------------
  // TRUST GAP
  // -------------------------

  if (detectedBrand && hostname) {
    const trusted =
      hostname === detectedBrand.domain ||
      hostname.endsWith(`.${detectedBrand.domain}`);

    if (!trusted) {
      addSignal(
        signals,
        "Trust Gap detected",
        22,
        `${detectedBrand.name} is claimed, but the actual domain is ${hostname}.`
      );
    }
  }


  // -------------------------
  // CALCULATE RISK SCORE
  // -------------------------

  let score = signals.reduce(
    (total, signal) => total + signal.points,
    0
  );

  if (signals.length === 0) {
    score = 5;
  }

  score = Math.min(score, 100);


  // -------------------------
  // RISK LEVEL
  // -------------------------

  let level = "LOW";

  if (score >= 80) {
    level = "CRITICAL";
  } else if (score >= 60) {
    level = "HIGH";
  } else if (score >= 30) {
    level = "SUSPICIOUS";
  }


  // -------------------------
  // THREAT CATEGORY
  // -------------------------

  let category = "No major threat detected";

  const trustGapDetected = signals.some(
    (signal) => signal.label === "Trust Gap detected"
  );

  const credentialDetected = signals.some(
    (signal) => signal.label === "Credential request"
  );

  const financialDetected = signals.some(
    (signal) => signal.label === "Financial lure"
  );

  if (trustGapDetected && credentialDetected) {
    category = "Possible brand impersonation phishing";
  } else if (trustGapDetected) {
    category = "Possible brand impersonation";
  } else if (credentialDetected) {
    category = "Possible credential phishing";
  } else if (financialDetected && score >= 30) {
    category = "Possible reward / financial scam";
  } else if (score >= 30) {
    category = "Suspicious digital content";
  }


  return {
    score,
    level,
    category,
    signals,
  };
}


// --------------------------------------------------
// DISPLAY RESULT
// --------------------------------------------------

function showResult(result) {
  const resultContainer =
    document.getElementById("result");

  resultContainer.classList.remove("hidden");


  // Score
  document.getElementById(
    "score"
  ).textContent = `${result.score}/100`;


  // Level
  const levelElement =
    document.getElementById("level");

  levelElement.textContent = result.level;


  const colors = {
    LOW: "#2ed573",
    SUSPICIOUS: "#f6c344",
    HIGH: "#ff8c42",
    CRITICAL: "#ff4757",
  };

  levelElement.style.color =
    colors[result.level];


  // Category
  document.getElementById(
    "category"
  ).textContent = result.category;


  // Signals
  const signalsContainer =
    document.getElementById("signals");

  signalsContainer.innerHTML = "";


  if (result.signals.length === 0) {
    const safeMessage =
      document.createElement("div");

    safeMessage.className = "signal";

    const strong =
      document.createElement("strong");

    strong.textContent =
      "✓ No major suspicious signals";

    safeMessage.appendChild(strong);

    signalsContainer.appendChild(
      safeMessage
    );

    return;
  }


  result.signals.forEach((signal) => {
    const div =
      document.createElement("div");

    div.className = "signal";


    const strong =
      document.createElement("strong");

    strong.textContent =
      `${signal.label} (+${signal.points})`;


    const reason =
      document.createElement("small");

    reason.textContent =
      signal.reason;


    div.appendChild(strong);
    div.appendChild(reason);

    signalsContainer.appendChild(div);
  });
}


// --------------------------------------------------
// CURRENT TAB URL
// --------------------------------------------------

chrome.tabs.query(
  {
    active: true,
    currentWindow: true,
  },

  (tabs) => {
    if (tabs[0]?.url) {
      currentUrl = tabs[0].url;

      document.getElementById(
        "currentUrl"
      ).textContent = currentUrl;
    }
  }
);


// --------------------------------------------------
// LOAD TEXT SELECTED USING RIGHT CLICK
// --------------------------------------------------

// --------------------------------------------------
// LOAD + AUTO ANALYZE RIGHT-CLICKED TEXT
// --------------------------------------------------

chrome.storage.local.get(
  [
    "kavachSelectedText",
    "kavachAutoAnalyze"
  ],

  (result) => {
    if (result.kavachSelectedText) {
      const input =
        document.getElementById("input");

      input.value =
        result.kavachSelectedText;

      // Automatically analyze selected text
      if (result.kavachAutoAnalyze) {
        const analysis =
          analyze(result.kavachSelectedText);

        showResult(analysis);
      }

      // Clear stored temporary text
      chrome.storage.local.remove([
        "kavachSelectedText",
        "kavachAutoAnalyze"
      ]);
    }
  }
);


// --------------------------------------------------
// SCAN CURRENT URL BUTTON
// --------------------------------------------------

document
  .getElementById("scanUrl")
  .addEventListener(
    "click",

    () => {
      if (!currentUrl) {
        return;
      }

      const result =
        analyze(currentUrl);

      showResult(result);
    }
  );


// --------------------------------------------------
// ANALYZE MESSAGE / URL BUTTON
// --------------------------------------------------

document
  .getElementById("analyzeText")
  .addEventListener(
    "click",

    () => {
      const input =
        document.getElementById("input");

      const value =
        input.value.trim();

      if (!value) {
        return;
      }

      const result =
        analyze(value);

      showResult(result);
    }
  );