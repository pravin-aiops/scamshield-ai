import { Fragment, useEffect, useRef, useState, type CSSProperties } from "react";
import "./App.css";

/* ------------------------------------------------------------------ types */

type DetectedLanguage = "en" | "hi" | "hinglish";
type RiskLevel = "low" | "medium" | "high";
type AppMode = "check" | "ask";
type UiLanguage = "en" | "hi";

type Finding = {
  category: string;
  label: string;
  evidence: string;
  why: string;
};

type UrlStatus = "threat_found" | "no_known_threat" | "unavailable" | "not_checked";

type UrlReputation = {
  status: "not_checked" | "unavailable" | "unsafe" | "no_known_threat";
  checked_count: number;
  url_count: number;
  message: string;
  urls: { url: string; status: UrlStatus }[];
};

type AiAnalysis = {
  status: "available" | "unavailable" | "skipped";
  summary: string;
  summary_source: "ai" | "rules";
};

type CheckResult = {
  mode: "check";
  detected_language: DetectedLanguage;
  risk_score: number;
  risk_level: RiskLevel;
  findings: Finding[];
  actions: string[];
  url_reputation: UrlReputation | null;
  assessment_note: string;
  ai_analysis: AiAnalysis;
  suggest_ask_mode: boolean;
  sender_context: {
    unknown: boolean;
    source: "user" | "text";
    title: string;
    text: string;
    steps: string[];
  } | null;
};

type AskResult = {
  mode: "ask";
  detected_language: DetectedLanguage;
  in_scope: boolean;
  scope_source?: "keywords" | "ai" | "unavailable";
  answer: {
    text: string;
    steps: string[];
    source: "ai" | "knowledge_base" | "scope";
  };
  suggest_check_mode: boolean;
};

type ApiResult = CheckResult | AskResult;

const API_URL = (import.meta.env.VITE_API_URL || "/api").replace(/\/$/, "");

/* ------------------------------------------- result text (message language) */

const resultText = {
  en: {
    reportTitle: "Your safety report",
    zoneLow: "Low 0–24",
    zoneMid: "Caution 25–49",
    zoneHigh: "High 50+",
    zoneNote: "Not a percentage chance. A higher score means more warning signs were found.",
    whyTitle: "Why we say this",
    askNext: "Ask another question",
    answerTitle: "Answer to your question",
    riskHigh: "High risk — possible scam",
    riskMedium: "Caution — warning signs found",
    riskLow: "No strong warning signs found",
    assessment: "RISK ASSESSMENT",
    score: "Risk score",
    detected: "What was detected",
    inMessage: "In your message",
    why: "Why it matters",
    noFindings: "No suspicious patterns were found in the text.",
    actions: "What you should do",
    urlTitle: "Link check",
    urlSource: "Google Safe Browsing",
    urlThreat: "Known threat reported",
    urlClean: "No known threat reported",
    urlUnavailable: "Could not verify this link",
    urlNotChecked: "Not checked",
    urlThreatDetail: "Google lists a link in this message as unsafe. Do not open it.",
    urlCleanDetail: "Google has no record of this link as a threat. That is not the same as safe: new scam sites can be missed.",
    urlCleanButRisky: "This message itself shows warning signs, so do not trust the link just because it is not on Google's list.",
    urlShortNote: "A shortened link hides where it really goes, so this check says little about the real destination.",
    shareHint: "Opens WhatsApp with this warning ready to send. Your original message is not included.",
    urlUnavailableDetail: "The online check could not be completed. Treat unexpected links with caution.",
    urlNotCheckedDetail: "No link check was completed for this message.",
    urlCount: "checked",
    note: "Important note",
    aiLabel: "AI-written summary",
    rulesLabel: "Summary from scam-pattern rules",
    aiFailed: "The AI summary could not be generated, so a rule-based summary is shown. The score and warning signs below are not affected.",
    steps: "What to do",
    answerAi: "AI-written answer based on reviewed safety guidance",
    answerKb: "Reviewed safety guidance",
    hintAsk: "This looks like a question rather than a message to check.",
    hintAskButton: "Ask it as a question",
    hintCheck: "Your question includes a link. To check a suspicious message, use the message checker.",
    hintCheckButton: "Check a message",
    listen: "Listen",
    stop: "Stop",
    langName: "English",
    yourMessage: "Your message, with warning phrases marked",
    shareTitle: "Warn family and friends",
    shareWhatsapp: "Share on WhatsApp",
    shareCopy: "Copy warning",
    shareCopied: "Copied!",
    shareIntro: "⚠️ Scam alert (checked with ScamShield AI): a message I received shows warning signs —",
    shareAdvice:
      "Do not click links or share your OTP, PIN or password. If money is lost, call 1930 or report at cybercrime.gov.in.",
    helplineTitle: "Already shared an OTP or paid money?",
    helplineBody: "Act fast: call the national cybercrime helpline 1930 and report at cybercrime.gov.in.",
    callNow: "Call 1930",
    reportOnline: "Report online",
  },
  hi: {
    reportTitle: "आपकी सुरक्षा रिपोर्ट",
    zoneLow: "कम 0–24",
    zoneMid: "सावधानी 25–49",
    zoneHigh: "ज़्यादा 50+",
    zoneNote: "यह संभावना (प्रतिशत) नहीं है। जितना ज़्यादा स्कोर, उतने ज़्यादा चेतावनी संकेत मिले।",
    whyTitle: "हम ऐसा क्यों कह रहे हैं",
    askNext: "एक और सवाल पूछें",
    answerTitle: "आपके सवाल का जवाब",
    riskHigh: "ज़्यादा जोखिम — यह धोखाधड़ी हो सकती है",
    riskMedium: "सावधान रहें — चेतावनी संकेत मिले हैं",
    riskLow: "धोखाधड़ी के स्पष्ट संकेत नहीं मिले",
    assessment: "जोखिम का आकलन",
    score: "जोखिम स्कोर",
    detected: "क्या पता चला",
    inMessage: "आपके संदेश में",
    why: "यह क्यों मायने रखता है",
    noFindings: "टेक्स्ट में कोई संदिग्ध पैटर्न नहीं मिला।",
    actions: "आपको क्या करना चाहिए",
    urlTitle: "लिंक की जाँच",
    urlSource: "Google Safe Browsing",
    urlThreat: "ज्ञात खतरा दर्ज है",
    urlClean: "कोई ज्ञात खतरा दर्ज नहीं मिला",
    urlUnavailable: "इस लिंक की जाँच नहीं हो सकी",
    urlNotChecked: "जाँच नहीं हुई",
    urlThreatDetail: "Google ने इस संदेश के एक लिंक को असुरक्षित बताया है। उसे न खोलें।",
    urlCleanDetail: "Google के पास इस लिंक के खतरा होने का रिकॉर्ड नहीं है। इसका मतलब सुरक्षित होना नहीं है: नई नकली साइटें छूट सकती हैं।",
    urlCleanButRisky: "इस संदेश में खुद चेतावनी संकेत हैं, इसलिए सिर्फ़ इसलिए लिंक पर भरोसा न करें कि वह Google की सूची में नहीं है।",
    urlShortNote: "छोटा किया हुआ लिंक असली गंतव्य छिपा देता है, इसलिए यह जाँच असली जगह के बारे में बहुत कम बताती है।",
    shareHint: "व्हाट्सऐप खुलेगा और यह चेतावनी भेजने के लिए तैयार मिलेगी। आपका मूल संदेश इसमें शामिल नहीं है।",
    urlUnavailableDetail: "ऑनलाइन जाँच पूरी नहीं हो सकी। अनजान लिंक से सावधान रहें।",
    urlNotCheckedDetail: "इस संदेश के लिए लिंक की जाँच पूरी नहीं हुई।",
    urlCount: "जाँचे गए",
    note: "ज़रूरी बात",
    aiLabel: "AI द्वारा लिखा सारांश",
    rulesLabel: "स्कैम-पैटर्न नियमों से बना सारांश",
    aiFailed: "AI सारांश नहीं बन सका, इसलिए नियमों पर आधारित सारांश दिखाया गया है। नीचे का स्कोर और चेतावनी संकेत प्रभावित नहीं हैं।",
    steps: "क्या करें",
    answerAi: "जाँची-परखी सुरक्षा जानकारी पर आधारित AI का जवाब",
    answerKb: "जाँची-परखी सुरक्षा जानकारी",
    hintAsk: "यह जाँचने वाले संदेश से ज़्यादा एक सवाल जैसा लगता है।",
    hintAskButton: "सवाल की तरह पूछें",
    hintCheck: "आपके सवाल में लिंक है। संदिग्ध संदेश जाँचने के लिए संदेश जाँच का इस्तेमाल करें।",
    hintCheckButton: "संदेश जाँचें",
    listen: "सुनें",
    stop: "रोकें",
    langName: "हिन्दी",
    yourMessage: "आपका संदेश, चेतावनी वाले शब्द चिह्नित",
    shareTitle: "परिवार और दोस्तों को सावधान करें",
    shareWhatsapp: "व्हाट्सऐप पर भेजें",
    shareCopy: "चेतावनी कॉपी करें",
    shareCopied: "कॉपी हो गया!",
    shareIntro: "⚠️ स्कैम अलर्ट (ScamShield AI से जाँचा गया): मुझे मिले एक संदेश में चेतावनी संकेत हैं —",
    shareAdvice:
      "लिंक पर क्लिक न करें और ओटीपी, पिन या पासवर्ड न बताएँ। पैसे चले गए हों तो 1930 पर कॉल करें या cybercrime.gov.in पर शिकायत करें।",
    helplineTitle: "क्या ओटीपी बता दिया या पैसे भेज दिए?",
    helplineBody: "तुरंत राष्ट्रीय साइबर अपराध हेल्पलाइन 1930 पर कॉल करें और cybercrime.gov.in पर शिकायत करें।",
    callNow: "1930 पर कॉल करें",
    reportOnline: "ऑनलाइन शिकायत",
  },
  hinglish: {
    reportTitle: "Aapki safety report",
    zoneLow: "Low 0–24",
    zoneMid: "Savdhaan 25–49",
    zoneHigh: "High 50+",
    zoneNote: "Ye probability (percent) nahi hai. Score jitna zyada, utne zyada warning signs mile.",
    whyTitle: "Hum aisa kyun keh rahe hain",
    askNext: "Ek aur sawaal poochhein",
    answerTitle: "Aapke sawaal ka jawaab",
    riskHigh: "High risk — scam ho sakta hai",
    riskMedium: "Savdhaan — warning signs mile hain",
    riskLow: "Koi strong warning sign nahi mila",
    assessment: "RISK ASSESSMENT",
    score: "Risk score",
    detected: "Kya detect hua",
    inMessage: "Aapke message mein",
    why: "Ye kyun matter karta hai",
    noFindings: "Text mein koi suspicious pattern nahi mila.",
    actions: "Aapko kya karna chahiye",
    urlTitle: "Link check",
    urlSource: "Google Safe Browsing",
    urlThreat: "Known threat report hua hai",
    urlClean: "Koi known threat report nahi hua",
    urlUnavailable: "Is link ko verify nahi kar paaye",
    urlNotChecked: "Check nahi hua",
    urlThreatDetail: "Google ne is message ke ek link ko unsafe bataya hai. Use na kholein.",
    urlCleanDetail: "Google ke paas is link ke threat hone ka record nahi hai. Iska matlab safe hona nahi hai: naye fake sites miss ho sakti hain.",
    urlCleanButRisky: "Is message mein khud warning signs hain, isliye sirf isliye link par bharosa na karein ki wo Google ki list mein nahi hai.",
    urlShortNote: "Chhota kiya hua link asli destination chhupa deta hai, isliye ye check asli jagah ke baare mein bahut kam batata hai.",
    shareHint: "WhatsApp khulega aur ye warning bhejne ke liye ready milegi. Aapka original message ismein shamil nahi hai.",
    urlUnavailableDetail: "Online check poora nahi ho paya. Unknown links se savdhaan rahein.",
    urlNotCheckedDetail: "Is message ke liye link check poora nahi hua.",
    urlCount: "checked",
    note: "Zaroori baat",
    aiLabel: "AI ka likha summary",
    rulesLabel: "Scam-pattern rules se bana summary",
    aiFailed: "AI summary nahi ban paya, isliye rules-based summary dikhayi gayi hai. Neeche ka score aur warning signs par iska asar nahi hai.",
    steps: "Kya karein",
    answerAi: "Reviewed safety guidance par based AI ka jawaab",
    answerKb: "Reviewed safety guidance",
    hintAsk: "Ye check karne wale message se zyada ek sawaal lagta hai.",
    hintAskButton: "Sawaal ki tarah poochhein",
    hintCheck: "Aapke sawaal mein link hai. Suspicious message check karne ke liye message checker use karein.",
    hintCheckButton: "Message check karein",
    listen: "Suniye",
    stop: "Roko",
    langName: "Hinglish",
    yourMessage: "Aapka message, warning phrases marked",
    shareTitle: "Family aur friends ko savdhaan karein",
    shareWhatsapp: "WhatsApp par share karein",
    shareCopy: "Warning copy karein",
    shareCopied: "Copy ho gaya!",
    shareIntro: "⚠️ Scam alert (ScamShield AI se check kiya): mujhe mile ek message mein warning signs hain —",
    shareAdvice:
      "Link par click na karein aur OTP, PIN ya password na batayein. Paise chale gaye hon to 1930 par call karein ya cybercrime.gov.in par report karein.",
    helplineTitle: "OTP bata diya ya paise bhej diye?",
    helplineBody: "Turant national cybercrime helpline 1930 par call karein aur cybercrime.gov.in par report karein.",
    callNow: "1930 par call karein",
    reportOnline: "Online report karein",
  },
} as const;

/* ------------------------------------------------------ interface text */

const uiText = {
  en: {
    description:
      "Paste a suspicious SMS, WhatsApp message, email or link to check for scam warning signs.",
    indiaTagline: "Pause. Verify. Protect your money.",
    badge: "YOUR PERSONAL SAFETY ASSISTANT",
    cardTitle: "Check if this message is safe",
    cardHint: "Paste a suspicious message, link or payment request below.",
    tabCheck: "Check a message",
    tabAsk: "Ask a scam question",
    modeCheck: "Paste an SMS, WhatsApp message, email or link to check warning signs.",
    modeAsk: "Ask about scams, fake emails, phishing, cybercrime or online safety. You can write in English, Hindi or Hinglish.",
    placeholderCheck: "Paste your message here...",
    placeholderAsk: "For example: How can I spot a fake email?",
    buttonCheck: "Analyse message",
    buttonAsk: "Get answer",
    loading: "Working on it...",
    clear: "Clear",
    privacy: "Analyse carefully. Never share OTPs, PINs or passwords.",
    empty: "Please enter some text first.",
    failed: "We couldn't complete this request. Check that the backend is running and try again.",
    rateLimited: "Too many requests. Please wait a minute and try again.",
    senderUnknown: "I don't know who sent this message",
    helplineBar: "Lost money to a scam? Call",
    helplineOr: "or report at",
    independent: "Independent tool · not a government service",
    madeForIndia: "Made for scams common in India",
    heroDevanagari: "रुको. सोचो. फिर क्लिक करो.",
    scamChips: ["UPI collect", "Bank KYC", "OTP", "Digital arrest", "Courier fee", "Job / task", "Lottery"],
    popularQuestions: "Popular questions",
    suggestions: [
      "How do I spot a fake email?",
      "I shared my OTP by mistake. What now?",
      "What is a digital arrest scam?",
      "Is a UPI collect request safe?",
    ],
    speechError: "Speech playback is not supported in this browser.",
    footer1: "Built to help people recognise potential scams.",
    footer2: "Stay alert. Verify independently. Never share OTPs or passwords.",
    scamTypesTitle: "Scams to watch out for in India",
    scamTypesHint: "Recognise the pattern. Take a moment before responding.",
    upiTitle: "UPI & payment fraud",
    upiDesc: "Collect requests, fake payment screenshots and requests to scan a QR to receive money.",
    kycTitle: "Bank KYC & OTP scams",
    kycDesc: "Threats to block your account, SIM or card unless you share an OTP or update details.",
    jobTitle: "Job & task scams",
    jobDesc: "Easy-income offers that ask for deposits, recharge payments or fees upfront.",
    prizeTitle: "Prize & parcel scams",
    prizeDesc: "Unexpected winnings, courier charges or small fees to release a supposed reward.",
    safetyTitle: "The 3-second safety check",
    safetyOne: "Never share an OTP, UPI PIN or screen with a caller.",
    safetyTwo: "To receive money, you do not need to enter your UPI PIN.",
    safetyThree: "Open your bank or service app yourself, don’t use a message link.",
    helpline: "Lost money to a scam? Call 1930 or report at cybercrime.gov.in right away.",
    themeDark: "Dark",
    themeLight: "Light",
    themeToDark: "Switch to dark theme",
    themeToLight: "Switch to light theme",
    switchLang: "Switch language to Hindi",
    navHome: "Home",
    navHow: "How it works",
    navScams: "Common scams",
    navTips: "Safety tips",
    navAbout: "About",
    navLabel: "Main navigation",
    howTitle: "How ScamShield works",
    howHint: "Three steps. A few seconds.",
    howSteps: [
      {
        icon: "📋",
        title: "Paste the message",
        text: "Copy the SMS, WhatsApp text, email or link into the box. You can write in English, Hindi or Hinglish.",
      },
      {
        icon: "🔍",
        title: "Scam-pattern rules check it",
        text: "Fixed rules look for pressure, requests for an OTP or money, fake authority and risky links. The score comes only from these rules. Links are also looked up on Google Safe Browsing.",
      },
      {
        icon: "✅",
        title: "You get a clear report",
        text: "You see the exact phrases that raised concern, why they matter and what to do next. An AI model only helps explain it in plain words.",
      },
    ],
    aboutTitle: "About ScamShield AI",
    aboutLead:
      "ScamShield AI explains why a message looks suspicious, in English, Hindi or Hinglish. It is built to help you pause before you click, pay or share a code.",
    aboutPoints: [
      "It is an automated pattern check, not proof. A low score does not mean a message or link is safe.",
      "Your message is not saved to a database; results may stay in server memory for a short time to respond faster. Links in a message are sent to Google Safe Browsing for checking when that check is turned on.",
      "When in doubt, verify through your bank's official app or the number printed on your card. If fraud has already happened, call 1930.",
    ],
  },
  hi: {
    description:
      "संदिग्ध एसएमएस, व्हाट्सऐप संदेश, ईमेल या लिंक यहाँ डालें। हम धोखाधड़ी के संभावित संकेतों की जाँच करेंगे।",
    indiaTagline: "रुकें। जाँचें। अपना पैसा सुरक्षित रखें।",
    badge: "आपका व्यक्तिगत सुरक्षा सहायक",
    cardTitle: "जाँचें कि यह संदेश सुरक्षित है या नहीं",
    cardHint: "संदिग्ध संदेश, लिंक या पेमेंट अनुरोध यहाँ पेस्ट करें।",
    tabCheck: "संदेश जाँचें",
    tabAsk: "स्कैम का सवाल पूछें",
    modeCheck: "एसएमएस, व्हाट्सऐप संदेश, ईमेल या लिंक पेस्ट करके चेतावनी संकेत जाँचें।",
    modeAsk: "स्कैम, फर्जी ईमेल, फिशिंग, साइबर अपराध या ऑनलाइन सुरक्षा के बारे में पूछें। आप हिन्दी, अंग्रेज़ी या हिंग्लिश में लिख सकते हैं।",
    placeholderCheck: "अपना संदेश यहाँ लिखें या पेस्ट करें...",
    placeholderAsk: "जैसे: फर्जी ईमेल कैसे पहचानें?",
    buttonCheck: "संदेश की जाँच करें",
    buttonAsk: "जवाब पाएँ",
    loading: "काम हो रहा है...",
    clear: "हटाएँ",
    privacy: "सावधानी से जाँचें। ओटीपी, पिन या पासवर्ड साझा न करें।",
    empty: "कृपया पहले कुछ लिखें।",
    failed: "यह अनुरोध पूरा नहीं हो सका। जाँचें कि बैकएंड चालू है, फिर दोबारा प्रयास करें।",
    rateLimited: "बहुत ज़्यादा अनुरोध हुए। कृपया एक मिनट रुककर दोबारा प्रयास करें।",
    senderUnknown: "मुझे नहीं पता कि यह संदेश किसने भेजा",
    helplineBar: "स्कैम में पैसे गए? कॉल करें",
    helplineOr: "या शिकायत करें",
    independent: "स्वतंत्र टूल · सरकारी सेवा नहीं",
    madeForIndia: "भारत में आम स्कैम के लिए बना",
    heroDevanagari: "रुको. सोचो. फिर क्लिक करो.",
    scamChips: ["UPI कलेक्ट", "बैंक KYC", "OTP", "डिजिटल अरेस्ट", "कूरियर फीस", "जॉब / टास्क", "लॉटरी"],
    popularQuestions: "लोकप्रिय सवाल",
    suggestions: [
      "फर्जी ईमेल कैसे पहचानें?",
      "गलती से ओटीपी बता दिया, अब क्या करूँ?",
      "डिजिटल अरेस्ट स्कैम क्या है?",
      "क्या UPI कलेक्ट रिक्वेस्ट सुरक्षित है?",
    ],
    speechError: "इस ब्राउज़र में आवाज़ सुनाने की सुविधा उपलब्ध नहीं है।",
    footer1: "लोगों को संभावित धोखाधड़ी पहचानने में मदद के लिए बनाया गया।",
    footer2: "सतर्क रहें। जानकारी की स्वतंत्र रूप से पुष्टि करें। ओटीपी या पासवर्ड साझा न करें।",
    scamTypesTitle: "भारत में इन धोखाधड़ियों से सावधान रहें",
    scamTypesHint: "पैटर्न पहचानें और जवाब देने से पहले थोड़ा रुकें।",
    upiTitle: "UPI और पेमेंट फ्रॉड",
    upiDesc: "पैसे पाने के नाम पर कलेक्ट रिक्वेस्ट, नकली पेमेंट स्क्रीनशॉट या QR स्कैन करने को कहना।",
    kycTitle: "बैंक KYC और OTP स्कैम",
    kycDesc: "खाता, SIM या कार्ड बंद करने की धमकी देकर OTP या निजी जानकारी माँगना।",
    jobTitle: "नौकरी और टास्क स्कैम",
    jobDesc: "आसान कमाई का लालच देकर पहले डिपॉज़िट, रिचार्ज या फीस माँगना।",
    prizeTitle: "इनाम और पार्सल स्कैम",
    prizeDesc: "अचानक इनाम जीतने या पार्सल छुड़ाने के लिए छोटी फीस माँगना।",
    safetyTitle: "3 सेकंड की सुरक्षा जाँच",
    safetyOne: "किसी कॉलर के साथ OTP, UPI PIN या स्क्रीन शेयर न करें।",
    safetyTwo: "पैसे पाने के लिए UPI PIN डालने की ज़रूरत नहीं होती।",
    safetyThree: "बैंक या सर्विस का ऐप खुद खोलें, मैसेज के लिंक से नहीं।",
    helpline: "स्कैम में पैसे गए? तुरंत 1930 पर कॉल करें या cybercrime.gov.in पर शिकायत करें।",
    themeDark: "डार्क",
    themeLight: "लाइट",
    themeToDark: "डार्क थीम चालू करें",
    themeToLight: "लाइट थीम चालू करें",
    switchLang: "भाषा अंग्रेज़ी में बदलें",
    navHome: "होम",
    navHow: "यह कैसे काम करता है",
    navScams: "आम स्कैम",
    navTips: "सुरक्षा सुझाव",
    navAbout: "हमारे बारे में",
    navLabel: "मुख्य नेविगेशन",
    howTitle: "ScamShield कैसे काम करता है",
    howHint: "तीन कदम। कुछ ही सेकंड।",
    howSteps: [
      {
        icon: "📋",
        title: "संदेश पेस्ट करें",
        text: "एसएमएस, व्हाट्सऐप संदेश, ईमेल या लिंक बॉक्स में डालें। आप हिन्दी, अंग्रेज़ी या हिंग्लिश में लिख सकते हैं।",
      },
      {
        icon: "🔍",
        title: "स्कैम-पैटर्न नियम जाँचते हैं",
        text: "तय नियम दबाव, ओटीपी या पैसे की माँग, नकली अधिकारी और जोखिम भरे लिंक ढूँढते हैं। स्कोर सिर्फ़ इन्हीं नियमों से बनता है। लिंक को Google Safe Browsing पर भी देखा जाता है।",
      },
      {
        icon: "✅",
        title: "आपको साफ़ रिपोर्ट मिलती है",
        text: "आप देखते हैं कि किन शब्दों से चिंता हुई, वे क्यों मायने रखते हैं और आगे क्या करना है। AI मॉडल सिर्फ़ उसे आसान भाषा में समझाने में मदद करता है।",
      },
    ],
    aboutTitle: "ScamShield AI के बारे में",
    aboutLead:
      "ScamShield AI हिन्दी, अंग्रेज़ी या हिंग्लिश में बताता है कि कोई संदेश संदिग्ध क्यों लगता है। इसका मकसद है कि आप क्लिक करने, पैसे भेजने या कोड बताने से पहले रुकें।",
    aboutPoints: [
      "यह एक स्वचालित पैटर्न जाँच है, सबूत नहीं। कम स्कोर का मतलब यह नहीं कि संदेश या लिंक सुरक्षित है।",
      "आपका संदेश किसी डेटाबेस में सेव नहीं होता; तेज़ जवाब के लिए नतीजे थोड़ी देर सर्वर की मेमोरी में रह सकते हैं। यह जाँच चालू होने पर संदेश के लिंक Google Safe Browsing को भेजे जाते हैं।",
      "शक हो तो बैंक के आधिकारिक ऐप या कार्ड पर छपे नंबर से पुष्टि करें। धोखाधड़ी हो चुकी हो तो 1930 पर कॉल करें।",
    ],
  },
} as const;

/* ----------------------------------------------------------------- helpers */

const NAV_ITEMS = [
  { id: "home", key: "navHome" },
  { id: "how-it-works", key: "navHow" },
  { id: "common-scams", key: "navScams" },
  { id: "safety-tips", key: "navTips" },
  { id: "about", key: "navAbout" },
] as const;

function riskLabel(level: RiskLevel, t: (typeof resultText)[DetectedLanguage]) {
  if (level === "high") return t.riskHigh;
  if (level === "medium") return t.riskMedium;
  return t.riskLow;
}

function urlStatusLabel(status: UrlStatus, t: (typeof resultText)[DetectedLanguage]) {
  if (status === "threat_found") return t.urlThreat;
  if (status === "no_known_threat") return t.urlClean;
  if (status === "unavailable") return t.urlUnavailable;
  return t.urlNotChecked;
}

function reputationHeadline(rep: UrlReputation, t: (typeof resultText)[DetectedLanguage]) {
  if (rep.status === "unsafe") return t.urlThreat;
  if (rep.status === "no_known_threat") return t.urlClean;
  if (rep.status === "unavailable") return t.urlUnavailable;
  return t.urlNotChecked;
}

function reputationDetail(rep: UrlReputation, t: (typeof resultText)[DetectedLanguage]) {
  if (rep.status === "unsafe") return t.urlThreatDetail;
  if (rep.status === "no_known_threat") return t.urlCleanDetail;
  if (rep.status === "unavailable") return t.urlUnavailableDetail;
  return t.urlNotCheckedDetail;
}

type Segment = { text: string; marked: boolean };

/** Split the user's message into plain and warning-marked parts using the
 *  evidence phrases the backend quoted. Returns null if nothing can be marked. */
function markedSegments(text: string, findings: Finding[]): Segment[] | null {
  const ranges: [number, number][] = [];

  for (const finding of findings) {
    const needle = (finding.evidence || "").replace(/…$/, "").trim();
    if (!needle) continue;

    // The backend collapses whitespace in quoted evidence, so match flexibly.
    const pattern = needle
      .split(/\s+/)
      .map((word) => word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
      .join("\\s+");

    for (const match of text.matchAll(new RegExp(pattern, "giu"))) {
      if (match.index !== undefined && match[0].length > 0) {
        ranges.push([match.index, match.index + match[0].length]);
      }
    }
  }

  if (ranges.length === 0) return null;

  ranges.sort((a, b) => a[0] - b[0]);
  const merged: [number, number][] = [];
  for (const range of ranges) {
    const last = merged[merged.length - 1];
    if (last && range[0] <= last[1]) last[1] = Math.max(last[1], range[1]);
    else merged.push([range[0], range[1]]);
  }

  const segments: Segment[] = [];
  let cursor = 0;
  for (const [start, end] of merged) {
    if (start > cursor) segments.push({ text: text.slice(cursor, start), marked: false });
    segments.push({ text: text.slice(start, end), marked: true });
    cursor = end;
  }
  if (cursor < text.length) segments.push({ text: text.slice(cursor), marked: false });

  return segments;
}

/** A short warning to forward. It never includes the original message. */
function buildShareText(result: CheckResult, t: (typeof resultText)[DetectedLanguage]) {
  const labels = result.findings
    .filter((item) => item.category !== "url")
    .map((item) => item.label)
    .slice(0, 4)
    .join(", ");

  return `${t.shareIntro} ${labels || riskLabel(result.risk_level, t)}. ${t.shareAdvice}`;
}

function speechLocale(language: DetectedLanguage) {
  return language === "hi" ? "hi-IN" : "en-IN";
}

function buildSpeech(result: ApiResult): string {
  const t = resultText[result.detected_language];

  if (result.mode === "ask") {
    return [result.answer.text, ...result.answer.steps].join(" ");
  }

  const parts = [
    `${riskLabel(result.risk_level, t)}. ${t.score}: ${result.risk_score} / 100.`,
    result.ai_analysis.summary,
    ...result.findings.map((item) => item.label),
    ...result.actions,
  ];

  return parts.join(" ");
}

/* -------------------------------------------------------------------- logo */

/** Rupee shield: the shield people already recognise, with ₹ and a saffron tick. */
function LogoMark({ size = 36 }: { size?: number }) {
  const shield = "M32 3 L57 11.5 V30 C57 45.5 46.5 55.5 32 61 C17.5 55.5 7 45.5 7 30 V11.5 Z";
  return (
    <svg viewBox="0 0 64 64" width={size} height={size} aria-hidden="true" focusable="false">
      <path d={shield} fill="#087a50" />
      <path d="M32 9 L51 15.4 V30 C51 42 43 50 32 54.6 C21 50 13 42 13 30 V15.4 Z" fill="#0b8f5e" />
      <text
        x="32"
        y="40"
        textAnchor="middle"
        fontFamily="'Segoe UI', 'Noto Sans', 'DejaVu Sans', Arial, sans-serif"
        fontWeight="700"
        fontSize="28"
        fill="#fff"
      >
        ₹
      </text>
      <circle cx="47" cy="47" r="10" fill="#f59a23" stroke="#fff" strokeWidth="2.5" />
      <path d="m42.3 47.2 3.2 3.2 5.6-6.4" fill="none" stroke="#fff" strokeWidth="2.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/* --------------------------------------------------------------------- app */

function App() {
  const [message, setMessage] = useState("");
  const [mode, setMode] = useState<AppMode>("check");
  const [result, setResult] = useState<ApiResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [submittedMessage, setSubmittedMessage] = useState("");
  const [copied, setCopied] = useState(false);
  const [senderUnknown, setSenderUnknown] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("home");
  const resultRef = useRef<HTMLElement | null>(null);
  const [uiLanguage, setUiLanguage] = useState<UiLanguage>("en");
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    try {
      return localStorage.getItem("scamshield-theme") === "dark" ? "dark" : "light";
    } catch {
      return "light";
    }
  });

  const ui = uiText[uiLanguage];

  function toggleTheme() {
    setTheme((current) => {
      const next = current === "light" ? "dark" : "light";
      try {
        localStorage.setItem("scamshield-theme", next);
      } catch {
        /* storage may be disabled */
      }
      return next;
    });
  }

  function stopSpeaking() {
    if ("speechSynthesis" in window) {
      window.speechSynthesis.cancel();
    }
  }

  function changeUiLanguage(next: UiLanguage) {
    stopSpeaking();
    setError("");
    setUiLanguage(next);

    // The report is written in the language the person picked, so re-run the
    // current check when they switch while a result is on screen.
    if (result && message.trim()) {
      void submit(mode, undefined, next);
    }
  }

  function switchMode(next: AppMode) {
    setMode(next);
    setResult(null);
    setError("");
    stopSpeaking();
  }

  async function submit(modeToUse: AppMode = mode, textOverride?: string, languageOverride?: UiLanguage) {
    const text = (textOverride ?? message).trim();

    if (!text) {
      setError(ui.empty);
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
        // Hindi chosen in the page toggle means a Hindi report. Otherwise the
        // backend detects English / Hindi / Hinglish from the message itself.
        body: JSON.stringify({
          message: text,
          language: (languageOverride ?? uiLanguage) === "hi" ? "hi" : "auto",
          mode: modeToUse,
          sender: modeToUse === "check" && senderUnknown ? "unknown" : undefined,
        }),
      });

      if (response.status === 429) {
        setError(ui.rateLimited);
        return;
      }

      if (!response.ok) throw new Error("Request failed");

      const data: ApiResult = await response.json();
      setSubmittedMessage(text);
      setResult(data);
    } catch {
      setError(ui.failed);
    } finally {
      setLoading(false);
    }
  }

  function askSuggestion(question: string) {
    setMessage(question);
    void submit("ask", question);
  }

  async function copyWarning(text: string) {
    let ok = false;

    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch {
      // Older browsers or non-secure pages: fall back to a temporary textarea.
      try {
        const area = document.createElement("textarea");
        area.value = text;
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        area.select();
        ok = document.execCommand("copy");
        document.body.removeChild(area);
      } catch {
        ok = false;
      }
    }

    if (ok) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    }
  }

  function retryInMode(next: AppMode) {
    setMode(next);
    void submit(next);
  }

  function speakResult() {
    if (!result || !("speechSynthesis" in window)) {
      setError(ui.speechError);
      return;
    }

    window.speechSynthesis.cancel();

    const speech = new SpeechSynthesisUtterance(buildSpeech(result));
    speech.lang = speechLocale(result.detected_language);
    speech.rate = 0.9;

    window.speechSynthesis.speak(speech);
  }

  // Highlight the nav link of the section the reader is currently in.
  useEffect(() => {
    function update() {
      let current: string = NAV_ITEMS[0].id;

      for (const item of NAV_ITEMS) {
        const element = document.getElementById(item.id);
        if (element && element.getBoundingClientRect().top <= 140) current = item.id;
      }

      // At the very bottom the short last section may never reach the top.
      if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4) {
        current = NAV_ITEMS[NAV_ITEMS.length - 1].id;
      }

      setActiveSection(current);
    }

    update();
    window.addEventListener("scroll", update, { passive: true });
    window.addEventListener("resize", update);
    return () => {
      window.removeEventListener("scroll", update);
      window.removeEventListener("resize", update);
    };
  }, []);

  // Bring a new result into view (matters on phones, where it renders below the form).
  useEffect(() => {
    if (result && resultRef.current) {
      resultRef.current.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }, [result]);

  const t = result ? resultText[result.detected_language] : resultText.en;

  // A plain "link" finding is redundant when a more specific link finding explains it.
  const shownFindings =
    result && result.mode === "check"
      ? result.findings.filter(
          (item) =>
            !(
              item.category === "url" &&
              result.findings.some((other) => other.category === "short_url" || other.category === "lookalike_domain")
            ),
        )
      : [];

  // On phones the main actions stay in a fixed bar while a risky result is shown.
  const hasActionBar = !!result && result.mode === "check" && result.risk_level !== "low";

  return (
    <main className={`app-shell${hasActionBar ? " has-action-bar" : ""}`} data-theme={theme}>
      <div className="help-bar">
        <span>
          📞 {ui.helplineBar} <a href="tel:1930">1930</a> · {ui.helplineOr}{" "}
          <a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer">
            cybercrime.gov.in
          </a>
        </span>
        <span className="help-bar-note">{ui.independent}</span>
      </div>

      <header className="topbar">
        <a className="brand" href="#home" aria-label="ScamShield AI home">
          <span className="brand-icon" aria-hidden="true">
            <LogoMark size={38} />
          </span>
          <span className="brand-text">
            <span className="brand-name">
              ScamShield <strong>AI</strong>
            </span>
            <small lang="hi">स्कैमशील्ड · भारत के लिए</small>
          </span>
        </a>

        <nav className="main-nav" aria-label={ui.navLabel}>
          {NAV_ITEMS.map((item) => (
            <a
              key={item.id}
              href={`#${item.id}`}
              className={activeSection === item.id ? "active" : undefined}
              aria-current={activeSection === item.id ? "location" : undefined}
            >
              {ui[item.key]}
            </a>
          ))}
        </nav>

        <div className="header-actions">
          <button
            type="button"
            className="theme-button"
            onClick={toggleTheme}
            aria-label={theme === "light" ? ui.themeToDark : ui.themeToLight}
            title={theme === "light" ? ui.themeToDark : ui.themeToLight}
          >
            <span aria-hidden="true">{theme === "light" ? "☾" : "☀"}</span>
            <span>{theme === "light" ? ui.themeDark : ui.themeLight}</span>
          </button>
          <div className="lang-switch" role="group" aria-label={ui.switchLang}>
            <button
              type="button"
              className={uiLanguage === "en" ? "lang-option active" : "lang-option"}
              aria-pressed={uiLanguage === "en"}
              onClick={() => changeUiLanguage("en")}
            >
              English
            </button>
            <button
              type="button"
              className={uiLanguage === "hi" ? "lang-option active" : "lang-option"}
              aria-pressed={uiLanguage === "hi"}
              onClick={() => changeUiLanguage("hi")}
              lang="hi"
            >
              हिन्दी
            </button>
          </div>
        </div>
      </header>

      <section className={result ? "hero has-result" : "hero"} id="home">
        <div className="workspace-grid">
          {!result && (
            <div className="hero-copy">
              <div className="in-badge">
                <span className="in-dots" aria-hidden="true">
                  <i style={{ background: "#f59a23" }} />
                  <i style={{ background: "#fff", boxShadow: "inset 0 0 0 1px #c3cdc7" }} />
                  <i style={{ background: "#138808" }} />
                </span>
                {ui.madeForIndia}
              </div>
              <h1 className="brand-hero-heading">
                <span>Ruko. Socho.</span>
                <span className="hero-highlight">Phir Click Karo.</span>
              </h1>
              <p className="hero-devanagari" lang="hi">
                {ui.heroDevanagari}
              </p>
              <p className="hero-lead">{ui.description}</p>
              <ul className="scam-chips" aria-label={ui.scamTypesTitle}>
                {ui.scamChips.map((chip) => (
                  <li key={chip}>{chip}</li>
                ))}
              </ul>
            </div>
          )}

          <section className="analyser-card" id="checker">
            <div className="analyser-heading">
              <span className="analyser-mark" aria-hidden="true">🛡</span>
              <div>
                <label htmlFor="message">{ui.cardTitle}</label>
                <p>{ui.cardHint}</p>
              </div>
            </div>

            <div className="mode-tabs" role="tablist" aria-label="Choose ScamShield mode">
              <button
                type="button"
                role="tab"
                aria-selected={mode === "check"}
                className={mode === "check" ? "mode-tab active" : "mode-tab"}
                onClick={() => switchMode("check")}
              >
                {ui.tabCheck}
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={mode === "ask"}
                className={mode === "ask" ? "mode-tab active" : "mode-tab"}
                onClick={() => switchMode("ask")}
              >
                {ui.tabAsk}
              </button>
            </div>

            <p className="mode-description">{mode === "ask" ? ui.modeAsk : ui.modeCheck}</p>

            {mode === "ask" && !message.trim() && (
              <div className="suggestion-row" aria-label={ui.popularQuestions}>
                <span className="suggestion-title">{ui.popularQuestions}</span>
                {ui.suggestions.map((question) => (
                  <button
                    key={question}
                    type="button"
                    className="suggestion-chip"
                    onClick={() => askSuggestion(question)}
                    disabled={loading}
                  >
                    {question}
                  </button>
                ))}
              </div>
            )}

            <textarea
              id="message"
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              placeholder={mode === "ask" ? ui.placeholderAsk : ui.placeholderCheck}
              maxLength={10000}
              rows={6}
              aria-describedby="message-privacy-note"
            />

            {mode === "check" && (
              <label className="sender-check">
                <input
                  type="checkbox"
                  checked={senderUnknown}
                  onChange={(event) => setSenderUnknown(event.target.checked)}
                />
                <span>{ui.senderUnknown}</span>
              </label>
            )}

            <div className="input-footer">
              <span>{message.length}/10000</span>
              <button
                type="button"
                className="clear-button"
                onClick={() => {
                  setMessage("");
                  setResult(null);
                  setError("");
                  stopSpeaking();
                }}
              >
                {ui.clear}
              </button>
            </div>

            <p className="message-privacy-note" id="message-privacy-note">
              🔒 {ui.privacy}
            </p>

            <button type="button" className="analyse-button" onClick={() => void submit()} disabled={loading}>
              {loading ? ui.loading : mode === "ask" ? ui.buttonAsk : `🛡️ ${ui.buttonCheck}`}
            </button>

            {error && (
              <p className="error-message" role="alert">
                {error}
              </p>
            )}
          </section>

          {loading && (
            <section className="result-section" aria-live="polite" aria-busy="true">
              <div className="skeleton-card" role="status" aria-label={ui.loading}>
                <div className="skeleton-ring" />
                <div className="skeleton-lines">
                  <span style={{ width: "38%" }} />
                  <span style={{ width: "86%" }} />
                  <span style={{ width: "64%" }} />
                </div>
              </div>
            </section>
          )}

          {result && (
            <section className="result-section" aria-live="polite" id="safety-report" ref={resultRef}>
              {result.mode === "check" && (
                <>
                  <article className={`verdict-banner risk-${result.risk_level}`}>
                    <div
                      className="verdict-ring"
                      role="img"
                      aria-label={`${t.score}: ${result.risk_score}/100`}
                      style={{ "--score": Math.min(100, Math.max(0, result.risk_score)) } as CSSProperties}
                    >
                      <span>
                        <strong>{result.risk_score}</strong>
                        <small>/100</small>
                      </span>
                    </div>

                    <div className="verdict-main">
                      <span className="result-eyebrow">{t.assessment}</span>
                      <h2>{riskLabel(result.risk_level, t)}</h2>

                      <span className={`source-badge source-${result.ai_analysis.summary_source}`}>
                        {result.ai_analysis.summary_source === "ai" ? "✦ " + t.aiLabel : t.rulesLabel}
                      </span>
                      <p className="verdict-summary">{result.ai_analysis.summary}</p>
                      {result.ai_analysis.status === "unavailable" && (
                        <p className="ai-fallback">{t.aiFailed}</p>
                      )}

                      {result.risk_level !== "low" && (
                        <div className="verdict-actions">
                          {result.risk_level === "high" && (
                            <a className="call-button" href="tel:1930">
                              📞 {t.callNow}
                            </a>
                          )}
                          <a
                            className="whatsapp-button"
                            href={`https://wa.me/?text=${encodeURIComponent(buildShareText(result, t))}`}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            {t.shareWhatsapp}
                          </a>
                        </div>
                      )}

                      <div className="score-zones" aria-hidden="true">
                        <span>{t.zoneLow}</span>
                        <span>{t.zoneMid}</span>
                        <span>{t.zoneHigh}</span>
                      </div>
                      <p className="score-note">{t.zoneNote}</p>

                      {result.suggest_ask_mode && (
                        <div className="hint-banner">
                          <span>{t.hintAsk}</span>
                          <button type="button" onClick={() => retryInMode("ask")}>
                            {t.hintAskButton}
                          </button>
                        </div>
                      )}
                    </div>
                  </article>

                  <div className="result-cols">
                    <article className="result-card why-card">
                      <h3 className="hx-title">{t.whyTitle}</h3>

                      {result.sender_context && (
                        <section className="sender-card" aria-label={result.sender_context.title}>
                          <strong>👤 {result.sender_context.title}</strong>
                          <p>{result.sender_context.text}</p>
                          <ul>
                            {result.sender_context.steps.map((step) => (
                              <li key={step}>{step}</li>
                            ))}
                          </ul>
                        </section>
                      )}

                      {(() => {
                        const segments = markedSegments(submittedMessage, result.findings);
                        if (!segments) return null;
                        return (
                          <>
                            <h4>{t.yourMessage}</h4>
                            <p className="marked-message">
                              {segments.map((segment, index) =>
                                segment.marked ? (
                                  <mark key={index}>{segment.text}</mark>
                                ) : (
                                  <Fragment key={index}>{segment.text}</Fragment>
                                ),
                              )}
                            </p>
                          </>
                        );
                      })()}

                      <h4>{t.detected}</h4>
                      {shownFindings.length === 0 ? (
                        <p className="no-findings">{t.noFindings}</p>
                      ) : (
                        <ul className="finding-list">
                          {shownFindings.map((finding, index) => (
                            <li key={finding.category} className="finding">
                              <details open={index === 0}>
                                <summary>
                                  <strong className="finding-label">{finding.label}</strong>
                                  {finding.evidence && (
                                    <span className="finding-evidence">
                                      <span>{t.inMessage}:</span> “{finding.evidence}”
                                    </span>
                                  )}
                                </summary>
                                <p className="finding-why">
                                  <span>{t.why}:</span> {finding.why}
                                </p>
                              </details>
                            </li>
                          ))}
                        </ul>
                      )}
                    </article>

                    <article className="result-card todo-card">
                      {result.actions.length > 0 && (
                        <>
                          <h3 className="hx-title">{t.actions}</h3>
                          <ul className="action-list">
                            {result.actions.map((action, index) => (
                              <li key={`action-${index}`}>{action}</li>
                            ))}
                          </ul>
                        </>
                      )}

                      {result.url_reputation && result.url_reputation.url_count > 0 && (
                        <section
                          className={`url-reputation reputation-${result.url_reputation.status}${
                            result.url_reputation.status === "no_known_threat" && result.risk_level !== "low"
                              ? " reputation-caution"
                              : ""
                          }`}
                          aria-live="polite"
                        >
                          <h4>
                            🔗 {t.urlTitle} <small>· {t.urlSource}</small>
                          </h4>
                          <h5>{reputationHeadline(result.url_reputation, t)}</h5>
                          <p>{reputationDetail(result.url_reputation, t)}</p>
                          {result.url_reputation.status === "no_known_threat" && result.risk_level !== "low" && (
                            <p className="url-extra-note">{t.urlCleanButRisky}</p>
                          )}
                          {result.findings.some((item) => item.category === "short_url") && (
                            <p className="url-extra-note">{t.urlShortNote}</p>
                          )}
                          <ul className="url-list">
                            {result.url_reputation.urls.map((item) => (
                              <li key={item.url} className={`url-item url-${item.status}`}>
                                <code>{item.url}</code>
                                <span>{urlStatusLabel(item.status, t)}</span>
                              </li>
                            ))}
                          </ul>
                          <p className="url-reputation-stats">
                            {result.url_reputation.checked_count}/{result.url_reputation.url_count} {t.urlCount}
                          </p>
                        </section>
                      )}
                    </article>
                  </div>

                  <article className="result-card hx-foot">
                    {result.risk_level === "high" && (
                      <section className="helpline-card" aria-label={t.helplineTitle}>
                        <strong>{t.helplineTitle}</strong>
                        <p>{t.helplineBody}</p>
                        <div className="helpline-buttons">
                          <a className="report-button" href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer">
                            {t.reportOnline}
                          </a>
                        </div>
                      </section>
                    )}

                    {result.risk_level !== "low" && (
                      <details className="share-details">
                        <summary>{t.shareTitle}</summary>
                        <section className="share-card" aria-label={t.shareTitle}>
                          <p>{buildShareText(result, t)}</p>
                          <p className="share-hint">{t.shareHint}</p>
                          <div className="share-buttons">
                            <button
                              type="button"
                              className="clear-button"
                              onClick={() => void copyWarning(buildShareText(result, t))}
                            >
                              {copied ? t.shareCopied : t.shareCopy}
                            </button>
                          </div>
                        </section>
                      </details>
                    )}

                    <aside className="note-box">
                      <strong>{t.note}</strong>
                      <p>{result.assessment_note}</p>
                    </aside>

                    <div className="result-actions">
                      <button type="button" className="listen-button" onClick={speakResult}>
                        🔊 {t.listen}
                      </button>
                      <button type="button" className="clear-button" onClick={stopSpeaking}>
                        {t.stop}
                      </button>
                    </div>
                  </article>
                </>
              )}

              {result.mode === "ask" && (
                <article className="result-card answer-card">
                  <span className={`source-badge source-${result.answer.source === "ai" ? "ai" : "rules"}`}>
                    {result.answer.source === "ai" ? "✦ " + t.answerAi : t.answerKb}
                  </span>
                  <h2 className="answer-title">{t.answerTitle}</h2>
                  <p className="answer-text">{result.answer.text}</p>

                  {result.answer.steps.length > 0 && (
                    <>
                      <h4>{t.steps}</h4>
                      <ol className="steps-list">
                        {result.answer.steps.map((step, index) => (
                          <li key={`step-${index}`}>{step}</li>
                        ))}
                      </ol>
                    </>
                  )}

                  {result.suggest_check_mode && (
                    <div className="hint-banner">
                      <span>{t.hintCheck}</span>
                      <button type="button" onClick={() => switchMode("check")}>
                        {t.hintCheckButton}
                      </button>
                    </div>
                  )}

                  <div className="followups">
                    <span className="suggestion-title">{t.askNext}</span>
                    <div className="suggestion-row">
                      {ui.suggestions.map((question) => (
                        <button
                          key={question}
                          type="button"
                          className="suggestion-chip"
                          onClick={() => askSuggestion(question)}
                          disabled={loading}
                        >
                          {question}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="result-actions">
                    <button type="button" className="listen-button" onClick={speakResult}>
                      🔊 {t.listen}
                    </button>
                    <button type="button" className="clear-button" onClick={stopSpeaking}>
                      {t.stop}
                    </button>
                  </div>
                </article>
              )}
            </section>
          )}
        </div>

        <section className="how-section" aria-labelledby="how-title" id="how-it-works">
          <div className="section-intro">
            <span className="section-kicker">SCAMSHIELD • HOW IT WORKS</span>
            <h2 id="how-title">{ui.howTitle}</h2>
            <p>{ui.howHint}</p>
          </div>
          <ol className="how-grid">
            {ui.howSteps.map((step, index) => (
              <li key={step.title} className="how-card">
                <span className="how-number" aria-hidden="true">
                  {index + 1}
                </span>
                <span className="how-icon" aria-hidden="true">
                  {step.icon}
                </span>
                <h3>{step.title}</h3>
                <p>{step.text}</p>
              </li>
            ))}
          </ol>
        </section>

        <section className="scam-awareness" aria-labelledby="scam-awareness-title" id="common-scams">
          <div className="section-intro">
            <span className="section-kicker">SCAMSHIELD • DIGITAL SAFETY</span>
            <h2 id="scam-awareness-title">{ui.scamTypesTitle}</h2>
            <p>{ui.scamTypesHint}</p>
          </div>
          <div className="scam-grid">
            <article className="scam-tile scam-tile-payment">
              <span className="scam-illustration" aria-hidden="true">📲</span>
              <h3>{ui.upiTitle}</h3>
              <p>{ui.upiDesc}</p>
            </article>
            <article className="scam-tile scam-tile-bank">
              <span className="scam-illustration" aria-hidden="true">🏦</span>
              <h3>{ui.kycTitle}</h3>
              <p>{ui.kycDesc}</p>
            </article>
            <article className="scam-tile scam-tile-job">
              <span className="scam-illustration" aria-hidden="true">💼</span>
              <h3>{ui.jobTitle}</h3>
              <p>{ui.jobDesc}</p>
            </article>
            <article className="scam-tile scam-tile-prize">
              <span className="scam-illustration" aria-hidden="true">🎁</span>
              <h3>{ui.prizeTitle}</h3>
              <p>{ui.prizeDesc}</p>
            </article>
          </div>
          <aside className="safety-strip" id="safety-tips">
            <div className="safety-strip-heading">
              <span aria-hidden="true">🔐</span>
              <h3>{ui.safetyTitle}</h3>
            </div>
            <ul>
              <li>{ui.safetyOne}</li>
              <li>{ui.safetyTwo}</li>
              <li>{ui.safetyThree}</li>
            </ul>
          </aside>
          <p className="helpline-strip">📞 {ui.helpline}</p>
        </section>

        <section className="about-section" aria-labelledby="about-title" id="about">
          <h2 id="about-title">{ui.aboutTitle}</h2>
          <p className="about-lead">{ui.aboutLead}</p>
          <ul className="about-points">
            {ui.aboutPoints.map((point) => (
              <li key={point}>{point}</li>
            ))}
          </ul>
        </section>
      </section>

      <footer className="footer">
        <p>{ui.footer1}</p>
        <p>{ui.footer2}</p>
      </footer>
    </main>
  );
}

export default App;
