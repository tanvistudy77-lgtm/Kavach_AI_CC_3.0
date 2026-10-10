let currentUrl = "";

const brands = [
  {
    name: "State Bank of India",
    words: ["sbi", "state bank of india"],
    domain: "sbi.co.in"
  },
  {
    name: "Paytm",
    words: ["paytm"],
    domain: "paytm.com"
  },
  {
    name: "HDFC Bank",
    words: ["hdfc", "hdfc bank"],
    domain: "hdfcbank.com"
  },
  {
    name: "ICICI Bank",
    words: ["icici", "icici bank"],
    domain: "icicibank.com"
  },
  {
    name: "Amazon",
    words: ["amazon"],
    domain: "amazon.in"
  }
];

function addSignal(signals, label, points, reason) {
  signals.push({
    label,
    points,
    reason
  });
}

function extractUrl(text) {
  const match = text.match(/https?:\/\/[^\s]+/i);

  if (!match) {
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(text.trim())) {
      return `https://${text.trim()}`;
    }

    return null;
  }

  return match[0].replace(/[),.;!?]+$/, "");
}

function analyze(input) {
  const text = input.toLowerCase();
  const signals = [];

  if (
    /\b(urgent|immediately|act now|today only|last chance|within \d+ hours?)\b/i.test(
      input
    )
  ) {
    addSignal(
      signals,
      "Artificial urgency",
      13,
      "Pressures the user to act quickly."
    );
  }

  if (
    /\b(blocked|suspended|deactivated|legal action|penalty|account closed)\b/i.test(
      input
    )
  ) {
    addSignal(
      signals,
      "Fear pressure",
      11,
      "Threatens negative consequences."
    );
  }

  if (
    /\b(otp|password|pin|cvv|kyc|login|bank details|card details)\b/i.test(
      input
    )
  ) {
    addSignal(
      signals,
      "Credential request",
      24,
      "References sensitive authentication information."
    );
  }

  if (
    /(₹|cashback|lottery|reward|prize|refund|upi|investment)/i.test(
      input
    )
  ) {
    addSignal(
      signals,
      "Financial lure",
      10,
      "Uses money or rewards to influence behaviour."
    );
  }

  const detectedBrand = brands.find((brand) =>
    brand.words.some((word) => text.includes(word))
  );

  const foundUrl = extractUrl(input);

  let hostname = "";

  if (foundUrl) {
    try {
      hostname = new URL(foundUrl)
        .hostname
        .toLowerCase()
        .replace(/^www\./, "");

      if (
        /\.(xyz|top|click|buzz|site|online|live)$/i.test(
          hostname
        )
      ) {
        addSignal(
          signals,
          "Suspicious domain ending",
          12,
          "The URL uses a domain ending commonly abused in deceptive links."
        );
      }

      if (
        /(secure|verify|update|kyc|login|account)/i.test(
          hostname
        )
      ) {
        addSignal(
          signals,
          "Trust-building domain words",
          12,
          "The domain contains words designed to appear trustworthy."
        );
      }

      if (
        /bit\.ly|tinyurl\.com|rb\.gy|cutt\.ly/i.test(
          hostname
        )
      ) {
        addSignal(
          signals,
          "Shortened URL",
          14,
          "The real destination may be hidden."
        );
      }
    } catch {
      addSignal(
        signals,
        "Malformed URL",
        15,
        "The link structure appears unusual."
      );
    }
  }

  if (detectedBrand && hostname) {
    const trusted =
      hostname === detectedBrand.domain ||
      hostname.endsWith(`.${detectedBrand.domain}`);

    if (!trusted) {
      addSignal(
        signals,
        "Trust Gap detected",
        22,
        `${detectedBrand.name} is claimed but the domain is ${hostname}.`
      );
    }
  }

  let score = signals.reduce(
    (total, signal) => total + signal.points,
    0
  );

  if (signals.length === 0) {
    score = 5;
  }

  score = Math.min(score, 100);

  let level = "LOW";

  if (score >= 80) level = "CRITICAL";
  else if (score >= 60) level = "HIGH";
  else if (score >= 30) level = "SUSPICIOUS";

  let category = "No major threat detected";

  if (
    signals.some((signal) =>
      signal.label.includes("Trust Gap")
    )
  ) {
    category = "Possible brand impersonation";
  } else if (
    signals.some((signal) =>
      signal.label.includes("Credential")
    )
  ) {
    category = "Possible credential phishing";
  } else if (score >= 30) {
    category = "Suspicious digital content";
  }

  return {
    score,
    level,
    category,
    signals
  };
}

function showResult(result) {
  const container = document.getElementById("result");

  container.classList.remove("hidden");

  document.getElementById("score").textContent =
    `${result.score}/100`;

  const level = document.getElementById("level");

  level.textContent = result.level;

  const colors = {
    LOW: "#2ed573",
    SUSPICIOUS: "#f6c344",
    HIGH: "#ff8c42",
    CRITICAL: "#ff4757"
  };

  level.style.color = colors[result.level];

  document.getElementById("category").textContent =
    result.category;

  const signalsContainer =
    document.getElementById("signals");

  signalsContainer.innerHTML = "";

  if (result.signals.length === 0) {
    signalsContainer.innerHTML =
      `<div class="signal"><strong>No suspicious signals</strong></div>`;
    return;
  }

  result.signals.forEach((signal) => {
    const div = document.createElement("div");

    div.className = "signal";

    div.innerHTML = `
      <strong>${signal.label} (+${signal.points})</strong>
      <small>${signal.reason}</small>
    `;

    signalsContainer.appendChild(div);
  });
}

chrome.tabs.query(
  {
    active: true,
    currentWindow: true
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

document
  .getElementById("scanUrl")
  .addEventListener("click", () => {
    if (!currentUrl) return;

    showResult(analyze(currentUrl));
  });

document
  .getElementById("analyzeText")
  .addEventListener("click", () => {
    const value =
      document.getElementById("input").value;

    if (!value.trim()) return;

    showResult(analyze(value));
  });