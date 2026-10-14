
import { useState } from "react";
import "./App.css";

type UrlReputation = {
  status:
    | "not_checked"
    | "unavailable"
    | "unsafe"
    | "no_known_threat";
  checked_count: number;
  threats: {
    url: string;
    threat_type?: string;
    platform_type?: string;
    threat_types?: string[];
  }[];
  message: string;
};

type AnalysisResult = {
  risk_score: number;
  risk_level: "low" | "medium" | "high";
  indicators: string[];
  recommendations: string[];
  url_reputation?: UrlReputation;
};

type Language = "en" | "hi";

const API_URL = "http://127.0.0.1:8000";

const hindiTranslations: Record<string, string> = {
  "Urgent or threatening language detected.":
    "संदेश में तुरंत कार्रवाई करने का दबाव बनाया गया है या धमकी दी गई है।",
  "The message requests sensitive credentials or an OTP.":
    "संदेश में गोपनीय जानकारी या ओटीपी माँगा गया है।",
  "The message may be impersonating an organisation or authority.":
    "संदेश में किसी संस्था या अधिकारी की पहचान का गलत इस्तेमाल हो सकता है।",
  "The message contains a URL. Its destination has not been verified.":
    "संदेश में एक लिंक है, जिसकी मंज़िल की अभी पुष्टि नहीं हुई है।",
  "Google Safe Browsing reported a known threat URL.":
    "Google Safe Browsing ने इस लिंक को संभावित खतरे के रूप में पहचाना है।",
  "Do not click links or send money based on this message.":
    "इस संदेश के आधार पर किसी लिंक पर क्लिक न करें और पैसे न भेजें।",
  "Never share an OTP, PIN, or password.":
    "अपना ओटीपी, पिन या पासवर्ड किसी के साथ साझा न करें।",
  "Verify the claim using the organisation's official app or website.":
    "संदेश में किए गए दावे की पुष्टि संबंधित संस्था की आधिकारिक वेबसाइट या ऐप से करें।",
  "Do not open this URL or enter personal information.":
    "इस लिंक को न खोलें और इसमें अपनी निजी जानकारी दर्ज न करें।",
  "Do not open an unexpected link until you verify its destination independently.":
    "अनजान लिंक को खोलने से पहले उसकी मंज़िल की स्वतंत्र रूप से पुष्टि करें।",
};

function App() {
  const [message, setMessage] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [language, setLanguage] = useState<Language>("en");

  const copy = {
    en: {
      subtitle: "Check before you trust.",
      heading: "Is this message safe?",
      description:
        "Paste a suspicious SMS, WhatsApp message, email or link to check for scam warning signs.",
      placeholder: "Paste your message here...",
      analyse: "Analyse message",
      analysing: "Checking message...",
      clear: "Clear",
      result: "Your safety report",
      high: "High risk — possible scam",
      medium: "Caution — suspicious signs found",
      low: "No strong warning signs detected",
      score: "Risk score",
      assessment: "ASSESSMENT",
      why: "Why does this message look suspicious?",
      action: "What should you do?",
      listen: "Listen to explanation",
      stop: "Stop reading",
      disclaimer:
        "This is an automated risk assessment, not proof of fraud or a guarantee that a message is safe.",
      empty: "Please paste a message to analyse.",
      failed:
        "We couldn't analyse this message. Check that the backend is running and try again.",
      speechError: "Speech playback is not supported in this browser.",
      footer1: "Built to help people recognise potential scams.",
      footer2:
        "Stay alert. Verify independently. Never share OTPs or passwords.",
      resultLabel: "Result",
      warningSigns: "Warning signs",
      recommendations: "Recommendations",
      scoreOutOf: "out of 100",
      intro: "Result",
      adviceIntro: "Recommended actions",
      automated: "Please note, this is an automated assessment.",
      urlTitle: "URL reputation check",
      urlUnsafe: "Known threat detected",
      urlClean: "No known threat reported",
      urlUnavailable: "Unable to verify URL reputation",
      urlNotChecked: "URL reputation not checked",
      urlUnsafeDetail:
        "Google Safe Browsing reported a known threat. Avoid opening this link.",
      urlCleanDetail:
        "Google reported no known threat for the checked URL. This does not guarantee that the URL is safe.",
      urlUnavailableDetail:
        "The online reputation check could not be completed. Treat unexpected links with caution.",
      urlNotCheckedDetail: "No URL was available for reputation checking.",
      urlsChecked: "URLs checked",
      threatCount: "Threat matches",
      urlDisclaimer:
        "Reputation checks can miss new or unknown threats. Always verify links independently.",
    },
    hi: {
      subtitle: "भरोसा करने से पहले जाँचें।",
      heading: "क्या यह संदेश सुरक्षित है?",
      description:
        "संदिग्ध एसएमएस, व्हाट्सऐप संदेश, ईमेल या लिंक यहाँ डालें। हम धोखाधड़ी के संभावित संकेतों की जाँच करेंगे।",
      placeholder: "अपना संदेश यहाँ लिखें या पेस्ट करें...",
      analyse: "संदेश की जाँच करें",
      analysing: "संदेश की जाँच हो रही है...",
      clear: "हटाएँ",
      result: "आपकी सुरक्षा रिपोर्ट",
      high: "ज़्यादा जोखिम — यह धोखाधड़ी हो सकती है",
      medium: "सावधान रहें — संदिग्ध संकेत मिले हैं",
      low: "धोखाधड़ी के स्पष्ट संकेत नहीं मिले",
      score: "जोखिम स्कोर",
      assessment: "जोखिम का आकलन",
      why: "यह संदेश संदिग्ध क्यों है?",
      action: "आपको क्या करना चाहिए?",
      listen: "जानकारी सुनें",
      stop: "सुनना बंद करें",
      disclaimer:
        "यह स्वचालित जोखिम आकलन है। यह धोखाधड़ी का पक्का सबूत नहीं है और न ही संदेश के सुरक्षित होने की गारंटी है।",
      empty: "कृपया पहले जाँचने के लिए कोई संदेश लिखें या पेस्ट करें।",
      failed:
        "संदेश की जाँच नहीं हो सकी। जाँचें कि बैकएंड चालू है, फिर दोबारा प्रयास करें।",
      speechError: "इस ब्राउज़र में आवाज़ सुनाने की सुविधा उपलब्ध नहीं है।",
      footer1: "लोगों को संभावित धोखाधड़ी पहचानने में मदद के लिए बनाया गया।",
      footer2:
        "सतर्क रहें। जानकारी की स्वतंत्र रूप से पुष्टि करें। ओटीपी या पासवर्ड साझा न करें।",
      resultLabel: "परिणाम",
      warningSigns: "संदेह के कारण",
      recommendations: "सुरक्षा के लिए सुझाव",
      scoreOutOf: "100 में से",
      intro: "आपके संदेश का परिणाम",
      adviceIntro: "आपको ये कदम उठाने चाहिए",
      automated: "ध्यान दें, यह स्वचालित आकलन है।",
      urlTitle: "लिंक की सुरक्षा जाँच",
      urlUnsafe: "खतरे वाला लिंक मिला",
      urlClean: "कोई ज्ञात खतरा नहीं मिला",
      urlUnavailable: "लिंक की सुरक्षा जाँच नहीं हो सकी",
      urlNotChecked: "लिंक की सुरक्षा जाँच नहीं हुई",
      urlUnsafeDetail:
        "Google Safe Browsing ने इस लिंक को संभावित खतरे के रूप में पहचाना है। इसे न खोलें।",
      urlCleanDetail:
        "जाँचे गए लिंक के लिए Google ने कोई ज्ञात खतरा नहीं बताया। इसका मतलब यह नहीं है कि लिंक पूरी तरह सुरक्षित है।",
      urlUnavailableDetail:
        "ऑनलाइन सुरक्षा जाँच पूरी नहीं हो सकी। अनजान लिंक से सावधान रहें।",
      urlNotCheckedDetail:
        "सुरक्षा जाँच के लिए कोई लिंक उपलब्ध नहीं था।",
      urlsChecked: "जाँचे गए लिंक",
      threatCount: "खतरे के संकेत",
      urlDisclaimer:
        "नई या अज्ञात धोखाधड़ी वाली वेबसाइटें जाँच में छूट सकती हैं। लिंक की स्वतंत्र रूप से पुष्टि करें।",
    },
  }[language];

  function translateText(text: string): string {
    if (language === "en") return text;
    return hindiTranslations[text] ?? text;
  }

  async function analyseMessage() {
    if (!message.trim()) {
      setError(copy.empty);
      setResult(null);
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);
    stopSpeaking();

    try {
      const response = await fetch(`${API_URL}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: message.trim() }),
      });

      if (!response.ok) throw new Error("Analysis failed");

      const data: AnalysisResult = await response.json();
      setResult(data);
    } catch {
      setError(copy.failed);
    } finally {
      setLoading(false);
    }
  }

  function getRiskLabel(level: AnalysisResult["risk_level"]) {
    if (level === "high") return copy.high;
    if (level === "medium") return copy.medium;
    return copy.low;
  }

  function getUrlStatusLabel(status: UrlReputation["status"]) {
    switch (status) {
      case "unsafe":
        return copy.urlUnsafe;
      case "no_known_threat":
        return copy.urlClean;
      case "unavailable":
        return copy.urlUnavailable;
      default:
        return copy.urlNotChecked;
    }
  }

  function getUrlStatusDetail(status: UrlReputation["status"]) {
    switch (status) {
      case "unsafe":
        return copy.urlUnsafeDetail;
      case "no_known_threat":
        return copy.urlCleanDetail;
      case "unavailable":
        return copy.urlUnavailableDetail;
      default:
        return copy.urlNotCheckedDetail;
    }
  }

  function getExplanation(data: AnalysisResult) {
    const reasons = data.indicators.map(translateText).join(" ");
    const advice = data.recommendations.map(translateText).join(" ");

    if (language === "hi") {
      let explanation =
        `${copy.intro}: ${getRiskLabel(data.risk_level)}। ` +
        `${copy.score}: ${data.risk_score} ${copy.scoreOutOf}। ` +
        `${copy.warningSigns}: ${reasons}। ` +
        `${copy.adviceIntro}: ${advice}।`;

      if (data.url_reputation) {
        explanation +=
          ` ${copy.urlTitle}: ` +
          `${getUrlStatusLabel(data.url_reputation.status)}। ` +
          `${getUrlStatusDetail(data.url_reputation.status)}।`;
      }

      return `${explanation} ${copy.automated}`;
    }

    let explanation =
      `${copy.intro}: ${getRiskLabel(data.risk_level)}. ` +
      `${copy.score}: ${data.risk_score} ${copy.scoreOutOf}. ` +
      `${copy.warningSigns}: ${reasons}. ` +
      `${copy.adviceIntro}: ${advice}.`;

    if (data.url_reputation) {
      explanation +=
        ` ${copy.urlTitle}: ` +
        `${getUrlStatusLabel(data.url_reputation.status)}. ` +
        `${getUrlStatusDetail(data.url_reputation.status)}.`;
    }

    return `${explanation} ${copy.automated}`;
  }

  function speakResult() {
    if (!result || !("speechSynthesis" in window)) {
      setError(copy.speechError);
      return;
    }

    window.speechSynthesis.cancel();

    const speech = new SpeechSynthesisUtterance(getExplanation(result));
    speech.lang = language === "hi" ? "hi-IN" : "en-IN";
    speech.rate = 0.9;

    window.speechSynthesis.speak(speech);
  }

  function stopSpeaking() {
    if ("speechSynthesis" in window) {
      window.speechSynthesis.cancel();
    }
  }

  const riskLabel = result ? getRiskLabel(result.risk_level) : "";
  const reputation = result?.url_reputation;

  return (
    <main className="app-shell">
      <header className="topbar">
        <a className="brand" href="#" aria-label="ScamShield AI home">
          <span className="brand-icon">S</span>
          <span>
            ScamShield <strong>AI</strong>
          </span>
        </a>

        <button
          className="language-button"
          onClick={() => {
            stopSpeaking();
            setError("");
            setLanguage((current) => (current === "en" ? "hi" : "en"));
          }}
        >
          {language === "en" ? "हिन्दी" : "English"}
        </button>
      </header>

      <section className="hero">
        <div className="hero-badge">
          {language === "hi"
            ? "आपका व्यक्तिगत सुरक्षा सहायक"
            : "YOUR PERSONAL SAFETY ASSISTANT"}
        </div>

        <h1>{copy.heading}</h1>
        <p>{copy.description}</p>

        <section className="analyser-card">
          <label htmlFor="message">{copy.heading}</label>

          <textarea
            id="message"
            value={message}
            onChange={(event) => setMessage(event.target.value)}
            placeholder={copy.placeholder}
            maxLength={10000}
            rows={7}
          />

          <div className="input-footer">
            <span>{message.length}/10000</span>

            <button
              className="clear-button"
              onClick={() => {
                setMessage("");
                setResult(null);
                setError("");
                stopSpeaking();
              }}
            >
              {copy.clear}
            </button>
          </div>

          <button
            className="analyse-button"
            onClick={analyseMessage}
            disabled={loading}
          >
            {loading ? copy.analysing : `🛡️ ${copy.analyse}`}
          </button>

          {error && (
            <p className="error-message" role="alert">
              {error}
            </p>
          )}
        </section>
      </section>

      {result && (
        <section className="result-section" aria-live="polite">
          <h2>{copy.result}</h2>

          <article className={`result-card risk-${result.risk_level}`}>
            <div className="risk-heading">
              <div>
                <span className="result-eyebrow">{copy.assessment}</span>
                <h3>{riskLabel}</h3>
              </div>

              <div
                className="score-circle"
                aria-label={`${copy.score}: ${result.risk_score}/100`}
              >
                <strong>{result.risk_score}</strong>
                <span>/100</span>
              </div>
            </div>

            <div
              className="score-track"
              role="progressbar"
              aria-label={copy.score}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={Math.min(
                100,
                Math.max(0, result.risk_score)
              )}
            >
              <div
                className="score-fill"
                style={{
                  width: `${Math.min(
                    100,
                    Math.max(0, result.risk_score)
                  )}%`,
                }}
              />
            </div>

            {reputation && (
              <section
                className={`url-reputation reputation-${reputation.status}`}
                aria-live="polite"
              >
                <h4>🔗 {copy.urlTitle}</h4>
                <h5>{getUrlStatusLabel(reputation.status)}</h5>
                <p>{getUrlStatusDetail(reputation.status)}</p>

                <p className="url-reputation-stats">
                  {copy.urlsChecked}: {reputation.checked_count}
                  {reputation.status === "unsafe" &&
                    ` · ${copy.threatCount}: ${reputation.threats.length}`}
                </p>

                <p className="url-reputation-disclaimer">
                  {copy.urlDisclaimer}
                </p>
              </section>
            )}

            <h4>{copy.why}</h4>
            <ul>
              {result.indicators.map((indicator, index) => (
                <li key={index}>{translateText(indicator)}</li>
              ))}
            </ul>

            <h4>{copy.action}</h4>
            <ul className="advice-list">
              {result.recommendations.map((advice, index) => (
                <li key={index}>{translateText(advice)}</li>
              ))}
            </ul>

            <button className="listen-button" onClick={speakResult}>
              🔊 {copy.listen}
            </button>

            <button className="clear-button" onClick={stopSpeaking}>
              {copy.stop}
            </button>

            <p className="disclaimer">{copy.disclaimer}</p>
          </article>
        </section>
      )}

      <footer className="footer">
        <p>{copy.footer1}</p>
        <p>{copy.footer2}</p>
      </footer>
    </main>
  );
}

export default App;