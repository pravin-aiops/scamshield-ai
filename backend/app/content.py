"""Localized, human-reviewed content used by the report and question layers.

Everything here is keyed by *category* or *topic*, never by an exact user
message. Languages: "en" (English), "hi" (Hindi, Devanagari) and "hinglish"
(Hindi written in Roman script).

Helpline facts: 1930 is India's national cyber financial fraud helpline and
https://cybercrime.gov.in is the National Cyber Crime Reporting Portal.
"""

import re

LANGUAGES = ("en", "hi", "hinglish")

# --------------------------------------------------------------------------
# Findings: one entry per detector category (plus "url", "short_url" and
# "url_threat"). label = what was observed, why = why it matters,
# action = what the user should do about it.
# --------------------------------------------------------------------------
FINDING_CONTENT: dict[str, dict[str, dict[str, str]]] = {
    "credentials": {
        "en": {
            "label": "Asks for an OTP, password, PIN or CVV",
            "why": "Genuine banks and services never ask you to read out or send these. Anyone who does is trying to take over your account or approve a payment as you.",
            "action": "Never share an OTP, PIN, password or CVV with anyone, even if they say they are from your bank.",
        },
        "hi": {
            "label": "ओटीपी, पासवर्ड, पिन या CVV माँगा जा रहा है",
            "why": "असली बैंक या सर्विस ये जानकारी कभी बोलकर या मैसेज में नहीं माँगती। जो माँगता है, वह आपके खाते पर कब्ज़ा करना या आपकी ओर से पेमेंट मंज़ूर कराना चाहता है।",
            "action": "ओटीपी, पिन, पासवर्ड या CVV किसी को न बताएँ, भले ही वह खुद को आपके बैंक का बताए।",
        },
        "hinglish": {
            "label": "OTP, password, PIN ya CVV maanga ja raha hai",
            "why": "Asli bank ya service ye cheezein kabhi bolkar ya message mein nahi maangti. Jo maangta hai, wo aapke account par control ya aapki taraf se payment approve karwana chahta hai.",
            "action": "OTP, PIN, password ya CVV kisi ko na batayein, chahe wo khud ko aapke bank ka bataye.",
        },
    },
    "urgency": {
        "en": {
            "label": "Pressure or threat to act immediately",
            "why": "Scammers rush you, for example by threatening to block your account, so that you act before you can check.",
            "action": "Pause. Do not act under pressure; check the claim yourself through your bank’s official app or the number printed on your card.",
        },
        "hi": {
            "label": "तुरंत कदम उठाने का दबाव या धमकी",
            "why": "ठग जल्दबाज़ी कराते हैं, जैसे खाता बंद करने की धमकी देकर, ताकि आप जाँच किए बिना कदम उठा लें।",
            "action": "रुकें। दबाव में कुछ न करें; बैंक के आधिकारिक ऐप या कार्ड पर छपे नंबर से खुद पुष्टि करें।",
        },
        "hinglish": {
            "label": "Turant action lene ka pressure ya dhamki",
            "why": "Scammer jaldbaazi karwate hain, jaise account block karne ki dhamki dekar, taaki aap check kiye bina action le lein.",
            "action": "Ruk jaayein. Pressure mein kuch na karein; bank ki official app ya card par chhape number se khud verify karein.",
        },
    },
    "money_or_prize": {
        "en": {
            "label": "Prize, reward, refund or fee demand",
            "why": "Real prizes and refunds never require you to pay a fee or send money first.",
            "action": "Do not pay any fee or send money to claim a prize, refund or reward.",
        },
        "hi": {
            "label": "इनाम, रिवॉर्ड, रिफंड या फीस की माँग",
            "why": "असली इनाम या रिफंड पाने के लिए पहले फीस या पैसे नहीं माँगे जाते।",
            "action": "इनाम, रिफंड या रिवॉर्ड पाने के लिए कोई फीस न दें और पैसे न भेजें।",
        },
        "hinglish": {
            "label": "Prize, reward, refund ya fee ki demand",
            "why": "Asli prize ya refund ke liye pehle fee ya paise nahi maange jaate.",
            "action": "Prize, refund ya reward claim karne ke liye koi fee ya paise na bhejein.",
        },
    },
    "impersonation": {
        "en": {
            "label": "May be posing as a bank, official or authority",
            "why": "Fraudsters copy the tone of banks, KYC teams, police or government offices so the message looks trustworthy.",
            "action": "Contact the organisation yourself using its official app, website or a number you have verified independently.",
        },
        "hi": {
            "label": "बैंक, अधिकारी या सरकारी संस्था बनकर संपर्क करने का संकेत",
            "why": "ठग बैंक, KYC टीम, पुलिस या सरकारी दफ़्तर जैसी भाषा इस्तेमाल करते हैं ताकि संदेश भरोसेमंद लगे।",
            "action": "संस्था से खुद उसके आधिकारिक ऐप, वेबसाइट या स्वयं जाँचे हुए नंबर पर संपर्क करें।",
        },
        "hinglish": {
            "label": "Bank, official ya authority ban kar contact karne ka signal",
            "why": "Fraudster bank, KYC team, police ya government office jaisi bhasha use karte hain taaki message trustworthy lage.",
            "action": "Organisation se khud uski official app, website ya khud verify kiye hue number par contact karein.",
        },
    },
    "upi_payment_trick": {
        "en": {
            "label": "Unusual UPI instruction (PIN, collect request or QR)",
            "why": "You never need to enter a UPI PIN or scan a QR code to receive money. Those steps send money out of your account.",
            "action": "Decline unknown collect requests and never enter your UPI PIN to receive money. Check the details inside your own UPI app.",
        },
        "hi": {
            "label": "UPI से जुड़ा संदिग्ध निर्देश (पिन, कलेक्ट रिक्वेस्ट या QR)",
            "why": "पैसे पाने के लिए UPI पिन डालने या QR स्कैन करने की ज़रूरत नहीं होती। ये कदम आपके खाते से पैसे भेजते हैं।",
            "action": "अनजान कलेक्ट रिक्वेस्ट मंज़ूर न करें और पैसे पाने के लिए UPI पिन न डालें। जानकारी अपने UPI ऐप में जाँचें।",
        },
        "hinglish": {
            "label": "UPI se juda suspicious instruction (PIN, collect request ya QR)",
            "why": "Paise receive karne ke liye UPI PIN daalne ya QR scan karne ki zaroorat nahi hoti. Ye steps aapke account se paise bhejte hain.",
            "action": "Unknown collect request approve na karein aur paise receive karne ke liye UPI PIN na daalein. Details apni UPI app mein check karein.",
        },
    },
    "remote_access": {
        "en": {
            "label": "Asks you to install a remote-access or screen-sharing app",
            "why": "Apps like AnyDesk or TeamViewer let a stranger see your screen and OTPs and move money from your phone.",
            "action": "Do not install remote-access apps or share your screen with anyone who contacted you.",
        },
        "hi": {
            "label": "रिमोट-एक्सेस या स्क्रीन-शेयरिंग ऐप इंस्टॉल करने को कहा गया है",
            "why": "AnyDesk या TeamViewer जैसे ऐप से कोई अजनबी आपकी स्क्रीन और ओटीपी देख सकता है और आपके फ़ोन से पैसे निकाल सकता है।",
            "action": "जिसने आपसे संपर्क किया हो, उसके कहने पर रिमोट-एक्सेस ऐप इंस्टॉल न करें और स्क्रीन शेयर न करें।",
        },
        "hinglish": {
            "label": "Remote-access ya screen-sharing app install karne ko kaha gaya hai",
            "why": "AnyDesk ya TeamViewer jaise apps se koi stranger aapki screen aur OTP dekh sakta hai aur phone se paise nikal sakta hai.",
            "action": "Jis ne aapko contact kiya ho, uske kehne par remote-access app install na karein aur screen share na karein.",
        },
    },
    "digital_arrest": {
        "en": {
            "label": "Police, arrest or ‘digital arrest’ threat",
            "why": "‘Digital arrest’ is not a real legal process. Genuine agencies do not arrest people over a call or ask for money to close a case.",
            "action": "Do not transfer money. Hang up, and report it on 1930 or at cybercrime.gov.in.",
        },
        "hi": {
            "label": "पुलिस, गिरफ़्तारी या ‘डिजिटल अरेस्ट’ की धमकी",
            "why": "‘डिजिटल अरेस्ट’ कोई वैध कानूनी प्रक्रिया नहीं है। असली एजेंसियाँ कॉल पर गिरफ़्तारी नहीं करतीं और केस बंद करने के लिए पैसे नहीं माँगतीं।",
            "action": "पैसे ट्रांसफर न करें। कॉल काट दें और 1930 या cybercrime.gov.in पर शिकायत करें।",
        },
        "hinglish": {
            "label": "Police, arrest ya ‘digital arrest’ ki dhamki",
            "why": "‘Digital arrest’ koi real legal process nahi hai. Asli agencies call par arrest nahi karti aur case close karne ke liye paise nahi maangti.",
            "action": "Paise transfer na karein. Call kaat dein aur 1930 ya cybercrime.gov.in par report karein.",
        },
    },
    "job_task_scam": {
        "en": {
            "label": "Job or task offer asking for money upfront",
            "why": "Genuine employers do not ask you to pay deposits, recharges or fees to unlock tasks or earnings.",
            "action": "Do not pay any deposit. Verify the employer on its official website before sharing documents or money.",
        },
        "hi": {
            "label": "नौकरी या टास्क के नाम पर पहले पैसे माँगना",
            "why": "असली नियोक्ता टास्क या कमाई शुरू करने के लिए डिपॉज़िट, रिचार्ज या फीस नहीं माँगते।",
            "action": "कोई डिपॉज़िट न दें। दस्तावेज़ या पैसे देने से पहले नियोक्ता की आधिकारिक वेबसाइट से पुष्टि करें।",
        },
        "hinglish": {
            "label": "Job ya task ke naam par pehle paise maangna",
            "why": "Asli employer task ya earning shuru karne ke liye deposit, recharge ya fee nahi maangte.",
            "action": "Koi deposit na dein. Documents ya paise dene se pehle employer ko official website se verify karein.",
        },
    },
    "advance_fee": {
        "en": {
            "label": "Asks you to pay a fee before you can receive money, a prize or a parcel",
            "why": "Real prizes, refunds and deliveries do not require you to pay first. Scammers collect the fee and then ask for more, or disappear.",
            "action": "Do not pay any fee to receive a prize, refund, loan or parcel. Check with the company through its official website or app.",
        },
        "hi": {
            "label": "पैसे, इनाम या पार्सल पाने से पहले फीस माँगी जा रही है",
            "why": "असली इनाम, रिफंड या डिलीवरी के लिए पहले पैसे नहीं देने पड़ते। ठग फीस लेकर और पैसे माँगते हैं या गायब हो जाते हैं।",
            "action": "इनाम, रिफंड, लोन या पार्सल पाने के लिए कोई फीस न दें। कंपनी की आधिकारिक वेबसाइट या ऐप से पुष्टि करें।",
        },
        "hinglish": {
            "label": "Paise, prize ya parcel paane se pehle fee maangi ja rahi hai",
            "why": "Asli prize, refund ya delivery ke liye pehle paise nahi dene padte. Thag fee lekar aur paise maangte hain ya gayab ho jaate hain.",
            "action": "Prize, refund, loan ya parcel paane ke liye koi fee na dein. Company ki official website ya app se confirm karein.",
        },
    },
    "family_emergency": {
        "en": {
            "label": "Someone claiming to be a relative asks for money from a new number",
            "why": "A common scam: a message from an unknown number pretends to be your child or relative with a new phone and asks for urgent money.",
            "action": "Call your relative on their old, saved number before sending any money.",
        },
        "hi": {
            "label": "नए नंबर से रिश्तेदार बनकर पैसे माँगे जा रहे हैं",
            "why": "आम स्कैम: अनजान नंबर से बेटा, बेटी या रिश्तेदार बनकर नया फोन बताया जाता है और तुरंत पैसे माँगे जाते हैं।",
            "action": "पैसे भेजने से पहले अपने रिश्तेदार को उनके पुराने, सेव किए हुए नंबर पर कॉल करें।",
        },
        "hinglish": {
            "label": "Naye number se relative bankar paise maange ja rahe hain",
            "why": "Aam scam: unknown number se beta, beti ya relative bankar naya phone bataya jaata hai aur turant paise maange jaate hain.",
            "action": "Paise bhejne se pehle apne relative ko unke purane, saved number par call karein.",
        },
    },
    "lookalike_domain": {
        "en": {
            "label": "Link name looks like a known bank or brand, but is not its official address",
            "why": "Scammers register addresses that contain a real brand name, such as a bank, to make a fake page look genuine. This tool cannot confirm the page is fake, but the address is not the brand's own.",
            "action": "Do not open the link. Type the official website yourself or use the official app.",
        },
        "hi": {
            "label": "लिंक का नाम किसी जाने-माने बैंक या ब्रांड जैसा है, पर वह उसका आधिकारिक पता नहीं है",
            "why": "ठग असली ब्रांड का नाम डालकर पता बनाते हैं ताकि नकली पेज असली लगे। यह टूल पक्का नहीं कह सकता कि पेज नकली है, पर यह पता उस ब्रांड का अपना नहीं है।",
            "action": "लिंक न खोलें। आधिकारिक वेबसाइट खुद टाइप करें या आधिकारिक ऐप इस्तेमाल करें।",
        },
        "hinglish": {
            "label": "Link ka naam kisi jaane-maane bank ya brand jaisa hai, par wo uska official address nahi hai",
            "why": "Thag asli brand ka naam daalkar address banate hain taaki fake page asli lage. Ye tool pakka nahi keh sakta ki page fake hai, par ye address us brand ka apna nahi hai.",
            "action": "Link na kholein. Official website khud type karein ya official app use karein.",
        },
    },
    "courier_scam": {
        "en": {
            "label": "Parcel or courier problem with a link, fee or address update",
            "why": "Fake delivery notices push you to a link to pay a small fee or update your address, then steal your card details.",
            "action": "Check the delivery status in the courier’s official app or website, not through the message link.",
        },
        "hi": {
            "label": "पार्सल या कूरियर की समस्या के साथ लिंक, फीस या पता अपडेट",
            "why": "नकली डिलीवरी संदेश आपको छोटी फीस या पता अपडेट के नाम पर लिंक पर ले जाते हैं और फिर कार्ड की जानकारी चुरा लेते हैं।",
            "action": "डिलीवरी की स्थिति कूरियर के आधिकारिक ऐप या वेबसाइट पर देखें, संदेश के लिंक से नहीं।",
        },
        "hinglish": {
            "label": "Parcel ya courier problem ke saath link, fee ya address update",
            "why": "Fake delivery notice aapko chhoti fee ya address update ke naam par link par le jaate hain aur phir card details chura lete hain.",
            "action": "Delivery status courier ki official app ya website par check karein, message ke link se nahi.",
        },
    },
    "utility_disconnect": {
        "en": {
            "label": "Threat to cut electricity, gas or water supply unless you pay now",
            "why": "Fake bill messages claim your supply will be cut tonight so you pay in a hurry through a link or a number. Real providers do not cut supply on a same-day text.",
            "action": "Check your bill only in your provider’s official app or website, or call the number printed on your bill.",
        },
        "hi": {
            "label": "अभी भुगतान न करने पर बिजली, गैस या पानी की सप्लाई कटने की धमकी",
            "why": "नकली बिल संदेश कहते हैं कि आज रात सप्लाई कट जाएगी ताकि आप जल्दी में लिंक या नंबर से भुगतान कर दें। असली कंपनियाँ उसी दिन के एक संदेश पर सप्लाई नहीं काटतीं।",
            "action": "बिल अपनी कंपनी के आधिकारिक ऐप या वेबसाइट पर ही देखें, या बिल पर छपे नंबर पर कॉल करें।",
        },
        "hinglish": {
            "label": "Abhi payment na karne par bijli, gas ya paani ki supply kat jaane ki dhamki",
            "why": "Fake bill message kehte hain ki aaj raat supply kat jayegi, taaki aap jaldi me link ya number se payment kar dein. Asli company usi din ke ek message par supply nahi kaatti.",
            "action": "Bill sirf apni company ki official app ya website par dekhein, ya bill par chhape number par call karein.",
        },
    },
    "generic_scam_pattern": {
        "en": {
            "label": "A request for money or private details together with pressure or a threat",
            "why": "No single trick was recognised, but scams usually combine an ask for money or details with a deadline, a threat, a prize or a link to act on. This message does that.",
            "action": "Do not pay or share anything. Contact the person or company through an official app, website or a number you already trust.",
        },
        "hi": {
            "label": "पैसे या निजी जानकारी की माँग के साथ दबाव या धमकी",
            "why": "कोई एक जाना-पहचाना तरीका नहीं मिला, लेकिन ठगी में अक्सर पैसे या जानकारी की माँग के साथ समय-सीमा, धमकी, इनाम या लिंक पर जाने का दबाव मिला होता है। इस संदेश में यही है।",
            "action": "कुछ भी न भेजें और न बताएँ। उस व्यक्ति या कंपनी से आधिकारिक ऐप, वेबसाइट या अपने भरोसे के नंबर पर संपर्क करें।",
        },
        "hinglish": {
            "label": "Paise ya private details ki maang ke saath pressure ya dhamki",
            "why": "Koi ek jaana-pehchana tareeka nahi mila, lekin thagi me aksar paise ya details ki maang ke saath deadline, dhamki, inaam ya link par jaane ka pressure hota hai. Is message me wahi hai.",
            "action": "Kuch bhi pay ya share na karein. Us vyakti ya company se official app, website ya apne bharose ke number par contact karein.",
        },
    },
    "url": {
        "en": {
            "label": "Contains a link",
            "why": "A link in an unexpected message can lead to a fake site. This tool cannot tell where a link really goes.",
            "action": "Only open the link if you were expecting this message. Otherwise go to the official website or app yourself.",
        },
        "hi": {
            "label": "संदेश में लिंक है",
            "why": "अनपेक्षित संदेश का लिंक नकली वेबसाइट पर ले जा सकता है। यह टूल नहीं बता सकता कि लिंक असल में कहाँ जाता है।",
            "action": "लिंक तभी खोलें जब आप इस संदेश की उम्मीद कर रहे थे। नहीं तो आधिकारिक वेबसाइट या ऐप खुद खोलें।",
        },
        "hinglish": {
            "label": "Message mein link hai",
            "why": "Unexpected message ka link fake website par le ja sakta hai. Ye tool nahi bata sakta ki link asal mein kahan jaata hai.",
            "action": "Link tabhi kholein jab aap is message ka wait kar rahe the. Nahi to official website ya app khud kholein.",
        },
    },
    "url_threat": {
        "en": {
            "label": "Google Safe Browsing lists a link in this message as a known threat",
            "why": "Google flags sites it has seen used for phishing or malware. This is observed evidence from an online check, not a guess.",
            "action": "Do not open the link or enter any details on it. Delete the message and report it if it asks for money or codes.",
        },
        "hi": {
            "label": "Google Safe Browsing ने इस संदेश के एक लिंक को ज्ञात खतरे के रूप में दर्ज किया है",
            "why": "Google उन साइटों को चिह्नित करता है जो फिशिंग या मैलवेयर के लिए इस्तेमाल होती देखी गई हैं। यह ऑनलाइन जाँच से मिला प्रमाण है, अनुमान नहीं।",
            "action": "लिंक न खोलें और उस पर कोई जानकारी न डालें। संदेश हटाएँ, और अगर वह पैसे या कोड माँगता है तो शिकायत करें।",
        },
        "hinglish": {
            "label": "Google Safe Browsing ne is message ke ek link ko known threat bataya hai",
            "why": "Google un sites ko flag karta hai jo phishing ya malware ke liye use hoti dekhi gayi hain. Ye online check se mila evidence hai, andaza nahi.",
            "action": "Link na kholein aur us par koi details na daalein. Message delete karein, aur agar wo paise ya code maangta hai to report karein.",
        },
    },
    "short_url": {
        "en": {
            "label": "Uses a shortened link",
            "why": "Shortened links hide the real destination, which scammers use to disguise fake sites.",
            "action": "Avoid shortened links unless you can confirm the sender and where the link leads.",
        },
        "hi": {
            "label": "छोटा (शॉर्ट) लिंक इस्तेमाल हुआ है",
            "why": "शॉर्ट लिंक असली पता छिपा देते हैं, जिसका इस्तेमाल ठग नकली साइट छिपाने के लिए करते हैं।",
            "action": "जब तक भेजने वाले और लिंक के असली पते की पुष्टि न हो, शॉर्ट लिंक न खोलें।",
        },
        "hinglish": {
            "label": "Shortened link use hua hai",
            "why": "Shortened link asli address chhupa dete hain, jise scammer fake site chhupane ke liye use karte hain.",
            "action": "Jab tak sender aur link ke asli address ki confirmation na ho, shortened link na kholein.",
        },
    },
}

# Order in which findings are shown (most serious first).
FINDING_ORDER = [
    "url_threat",
    "digital_arrest",
    "credentials",
    "upi_payment_trick",
    "remote_access",
    "advance_fee",
    "money_or_prize",
    "family_emergency",
    "impersonation",
    "job_task_scam",
    "courier_scam",
    "utility_disconnect",
    "urgency",
    "generic_scam_pattern",
    "lookalike_domain",
    "short_url",
    "url",
]

# --------------------------------------------------------------------------
# One-line report summaries produced by rules (used when AI is skipped,
# unavailable, or fails validation).
# --------------------------------------------------------------------------
RISK_SUMMARY: dict[str, dict[str, str]] = {
    "en": {
        "low_clean": "No strong scam warning signs were found in this message. That does not guarantee it is genuine, so confirm anything unexpected through an official channel.",
        "low_minor": "Only minor signs were found, such as a link. Nothing here strongly suggests a scam, but confirm the sender if you were not expecting this message.",
        "medium": "Some warning signs were found. Do not act on this message until you have checked it through an official channel.",
        "high": "Several strong warning signs were found. Do not share codes, PINs or money, and verify through your bank’s official app or the number on your card.",
    },
    "hi": {
        "low_clean": "इस संदेश में धोखाधड़ी के कोई स्पष्ट संकेत नहीं मिले। इसका मतलब यह नहीं कि संदेश असली ही है, इसलिए कुछ भी अनपेक्षित हो तो आधिकारिक माध्यम से पुष्टि करें।",
        "low_minor": "केवल हल्के संकेत मिले, जैसे लिंक। इसमें ऐसा कुछ नहीं जो धोखाधड़ी की ओर पक्का इशारा करे, फिर भी अगर आप इस संदेश की उम्मीद नहीं कर रहे थे तो भेजने वाले की पुष्टि करें।",
        "medium": "कुछ चेतावनी संकेत मिले हैं। आधिकारिक माध्यम से जाँचने से पहले इस संदेश पर कोई कदम न उठाएँ।",
        "high": "कई गंभीर चेतावनी संकेत मिले हैं। कोड, पिन या पैसे साझा न करें, और बैंक के आधिकारिक ऐप या कार्ड पर छपे नंबर से पुष्टि करें।",
    },
    "hinglish": {
        "low_clean": "Is message mein scam ke koi strong warning signs nahi mile. Iska matlab ye nahi ki message asli hi hai, isliye kuch bhi unexpected ho to official channel se confirm karein.",
        "low_minor": "Sirf halke signs mile, jaise link. Isme aisa kuch nahi jo scam ki taraf pakka ishaara kare, phir bhi agar aap is message ka wait nahi kar rahe the to sender ko verify karein.",
        "medium": "Kuch warning signs mile hain. Official channel se check karne se pehle is message par koi action na lein.",
        "high": "Kai strong warning signs mile hain. Code, PIN ya paise share na karein, aur bank ki official app ya card par chhape number se verify karein.",
    },
}

ASSESSMENT_NOTE: dict[str, str] = {
    "en": "This is an automated check based on patterns in the text. It is not proof that a message is or is not a scam. New scam styles can be missed, and a low score does not mean a message or link is safe.",
    "hi": "यह टेक्स्ट के पैटर्न पर आधारित स्वचालित जाँच है। यह पक्का सबूत नहीं है कि संदेश धोखाधड़ी है या नहीं। नए तरह के स्कैम छूट सकते हैं, और कम स्कोर का मतलब यह नहीं कि संदेश या लिंक सुरक्षित है।",
    "hinglish": "Ye text ke patterns par based automated check hai. Ye pakka proof nahi ki message scam hai ya nahi. Naye tarah ke scam miss ho sakte hain, aur low score ka matlab ye nahi ki message ya link safe hai.",
}

GENERIC_ACTIONS: dict[str, list[str]] = {
    "en": [
        "Confirm the sender through an official app, website or a number you found yourself.",
        "Do not share OTPs, PINs, passwords or card details.",
    ],
    "hi": [
        "भेजने वाले की पुष्टि आधिकारिक ऐप, वेबसाइट या खुद खोजे हुए नंबर से करें।",
        "ओटीपी, पिन, पासवर्ड या कार्ड की जानकारी साझा न करें।",
    ],
    "hinglish": [
        "Sender ko official app, website ya khud dhoondhe hue number se confirm karein.",
        "OTP, PIN, password ya card details share na karein.",
    ],
}

OUT_OF_SCOPE: dict[str, str] = {
    "en": "This question is outside ScamShield’s scope. Please ask about scams, fraud, fake emails, phishing, cybercrime or online safety.",
    "hi": "यह सवाल ScamShield के दायरे से बाहर है। कृपया स्कैम, धोखाधड़ी, फर्जी ईमेल, फिशिंग, साइबर अपराध या ऑनलाइन सुरक्षा के बारे में पूछें।",
    "hinglish": "Ye question ScamShield ke scope ke bahar hai. Please scam, fraud, fake email, phishing, cybercrime ya online safety ke baare mein poochhein.",
}

# --------------------------------------------------------------------------
# Knowledge base for "Ask a scam question". The explanation text may be
# replaced by a model-generated answer; the steps are always these curated ones.
# --------------------------------------------------------------------------
TOPICS: dict[str, dict[str, dict]] = {
    "otp": {
        "en": {
            "answer": "A fake OTP scam tricks you into reading out or sending the one-time code your bank or an app has just texted you. With that code a fraudster can log in to your account or approve a payment as you. A typical story is a caller saying your account will be blocked unless you tell them the OTP right now. Genuine banks and apps never ask you to share an OTP; it is meant only for you to type in yourself.",
            "steps": [
                "Never tell anyone your OTP, even if they say they are from your bank.",
                "Hang up and call the number on your card or in your bank’s official app.",
                "If an OTP arrives that you did not request, change your password and tell your bank.",
            ],
        },
        "hi": {
            "answer": "फर्जी ओटीपी स्कैम में ठग आपसे वह वन-टाइम कोड बुलवा लेता है या मैसेज में मँगवा लेता है जो बैंक या ऐप ने अभी आपको भेजा है। इस कोड से वह आपके खाते में लॉगिन कर सकता है या आपकी ओर से पेमेंट मंज़ूर कर सकता है। आम तरीका यह है कि कॉल करने वाला कहे कि खाता बंद हो जाएगा, अभी ओटीपी बताइए। असली बैंक या ऐप कभी ओटीपी साझा करने को नहीं कहते; उसे सिर्फ़ आपको खुद डालना होता है।",
            "steps": [
                "अपना ओटीपी किसी को न बताएँ, भले ही वह खुद को आपके बैंक का बताए।",
                "कॉल काटकर कार्ड पर छपे नंबर या बैंक के आधिकारिक ऐप से खुद संपर्क करें।",
                "जो ओटीपी आपने माँगा नहीं, उसके आने पर पासवर्ड बदलें और बैंक को बताएँ।",
            ],
        },
        "hinglish": {
            "answer": "Fake OTP scam mein fraudster aapse wo one-time code bulwa leta hai ya message mein mangwa leta hai jo bank ya app ne abhi aapko bheja hai. Is code se wo aapke account mein login kar sakta hai ya aapki taraf se payment approve kar sakta hai. Aam tarika ye hai ki caller bole account block ho jayega, abhi OTP batao. Asli bank ya app kabhi OTP share karne ko nahi kehte; use sirf aapko khud enter karna hota hai.",
            "steps": [
                "Apna OTP kisi ko na batayein, chahe wo khud ko aapke bank ka bataye.",
                "Call kaat kar card par chhape number ya bank ki official app se khud contact karein.",
                "Jo OTP aapne maanga nahi, uske aane par password badlein aur bank ko batayein.",
            ],
        },
    },
    "shared_otp": {
        "en": {
            "answer": "If you shared an OTP, act immediately, because the first minutes matter most. Call your bank on the official number from your card or app and ask them to block the card, UPI and net banking. Then call the national cyber fraud helpline 1930 and file a report at cybercrime.gov.in. Check your account for transactions you did not make, and do not share anything more with the caller.",
            "steps": [
                "Call your bank’s official number now and ask to block the card, UPI and net banking.",
                "Call 1930 and file a complaint at cybercrime.gov.in; keep transaction IDs and screenshots.",
                "Change your banking passwords and UPI PIN, and do not take further calls from the same person.",
            ],
        },
        "hi": {
            "answer": "अगर आपने ओटीपी बता दिया है तो तुरंत कदम उठाएँ, क्योंकि शुरुआती कुछ मिनट सबसे ज़रूरी होते हैं। अपने कार्ड या बैंक ऐप में दिए आधिकारिक नंबर पर कॉल करके कार्ड, UPI और नेट बैंकिंग ब्लॉक करवाएँ। फिर राष्ट्रीय साइबर फ्रॉड हेल्पलाइन 1930 पर कॉल करें और cybercrime.gov.in पर शिकायत दर्ज करें। अपने खाते में ऐसे लेन-देन देखें जो आपने नहीं किए, और कॉल करने वाले को अब कुछ और न बताएँ।",
            "steps": [
                "अभी बैंक के आधिकारिक नंबर पर कॉल करके कार्ड, UPI और नेट बैंकिंग ब्लॉक करवाएँ।",
                "1930 पर कॉल करें और cybercrime.gov.in पर शिकायत दर्ज करें; ट्रांज़ैक्शन आईडी और स्क्रीनशॉट सँभालकर रखें।",
                "बैंकिंग पासवर्ड और UPI पिन बदलें, और उसी व्यक्ति की आगे की कॉल न उठाएँ।",
            ],
        },
        "hinglish": {
            "answer": "Agar aapne OTP bata diya hai to turant action lein, kyunki shuru ke kuch minute sabse important hote hain. Apne card ya bank app mein diye official number par call karke card, UPI aur net banking block karwayein. Phir national cyber fraud helpline 1930 par call karein aur cybercrime.gov.in par complaint file karein. Apne account mein aise transactions check karein jo aapne nahi kiye, aur caller ko ab kuch aur na batayein.",
            "steps": [
                "Abhi bank ke official number par call karke card, UPI aur net banking block karwayein.",
                "1930 par call karein aur cybercrime.gov.in par complaint file karein; transaction ID aur screenshots sambhal kar rakhein.",
                "Banking password aur UPI PIN badlein, aur usi person ki aage ki calls na uthayein.",
            ],
        },
    },
    "email": {
        "en": {
            "answer": "To spot a fake email, check the full sender address and domain, not just the display name, because scammers copy a bank’s name but use a different address. Warning signs include urgent threats, requests for a password or OTP, unexpected attachments, odd payment requests and links whose address does not match the company. For example, an email saying your account will be closed unless you click a link and sign in is a classic phishing attempt. Instead of clicking, open the company’s official website or app yourself.",
            "steps": [
                "Check the full sender address and the domain after the @ sign.",
                "Do not click links or open attachments you did not expect; open the official site or app yourself.",
                "Never enter a password or OTP from an email link, and report the email as phishing.",
            ],
        },
        "hi": {
            "answer": "फर्जी ईमेल पहचानने के लिए सिर्फ़ दिखने वाले नाम पर नहीं, बल्कि भेजने वाले का पूरा ईमेल पता और डोमेन देखें, क्योंकि ठग बैंक का नाम तो कॉपी कर लेते हैं पर पता अलग होता है। चेतावनी के संकेत हैं: तुरंत कार्रवाई की धमकी, पासवर्ड या ओटीपी की माँग, अनचाहे अटैचमेंट, अजीब पेमेंट अनुरोध और ऐसे लिंक जिनका पता कंपनी से मेल नहीं खाता। उदाहरण के लिए, ‘लिंक पर क्लिक करके लॉगिन करें वरना खाता बंद हो जाएगा’ वाला ईमेल फिशिंग का आम तरीका है। लिंक पर क्लिक करने के बजाय कंपनी की आधिकारिक वेबसाइट या ऐप खुद खोलें।",
            "steps": [
                "भेजने वाले का पूरा ईमेल पता और @ के बाद का डोमेन देखें।",
                "जिस लिंक या अटैचमेंट की उम्मीद न हो उसे न खोलें; आधिकारिक साइट या ऐप खुद खोलें।",
                "ईमेल के लिंक से पासवर्ड या ओटीपी कभी न डालें, और ईमेल को फिशिंग के रूप में रिपोर्ट करें।",
            ],
        },
        "hinglish": {
            "answer": "Fake email pehchanne ke liye sirf display name nahi, sender ka poora email address aur domain check karein, kyunki scammer bank ka naam copy kar lete hain par address alag hota hai. Warning signs hain: turant action ki dhamki, password ya OTP ki demand, unexpected attachment, ajeeb payment request aur aise links jinka address company se match nahi karta. Example ke liye, ‘link par click karke login karo warna account band ho jayega’ wala email phishing ka aam tarika hai. Link par click karne ke bajay company ki official website ya app khud kholein.",
            "steps": [
                "Sender ka poora email address aur @ ke baad ka domain check karein.",
                "Jis link ya attachment ki ummeed na ho use na kholein; official site ya app khud kholein.",
                "Email ke link se password ya OTP kabhi na daalein, aur email ko phishing ke roop mein report karein.",
            ],
        },
    },
    "upi": {
        "en": {
            "answer": "A UPI collect scam tricks you into approving a payment request by claiming it is needed to receive a refund, prize or other money. If you approve it and enter your UPI PIN, money leaves your account instead of arriving. For example, a buyer on a resale site says ‘approve this request to get your payment’, but the request is actually asking you to pay. You never need a UPI PIN or an approval to receive money.",
            "steps": [
                "Never enter your UPI PIN to receive money.",
                "Decline collect requests from people you do not know.",
                "Read the request inside your own UPI app: if it says you will pay, it is not a receipt.",
            ],
        },
        "hi": {
            "answer": "UPI कलेक्ट स्कैम में ठग रिफंड, इनाम या पैसे पाने के बहाने आपसे पेमेंट रिक्वेस्ट मंज़ूर करवाता है। अगर आप उसे मंज़ूर करके UPI पिन डालते हैं तो पैसे आपके खाते में आने के बजाय निकल जाते हैं। उदाहरण के लिए, सामान बेचते समय कोई खरीदार कहता है कि ‘पेमेंट पाने के लिए यह रिक्वेस्ट मंज़ूर करें’, जबकि वह रिक्वेस्ट असल में आपसे पैसे माँग रही होती है। पैसे पाने के लिए न UPI पिन की ज़रूरत होती है, न किसी रिक्वेस्ट को मंज़ूर करने की।",
            "steps": [
                "पैसे पाने के लिए कभी UPI पिन न डालें।",
                "अनजान लोगों की कलेक्ट रिक्वेस्ट अस्वीकार करें।",
                "रिक्वेस्ट अपने UPI ऐप में पढ़ें: अगर उसमें आपको पेमेंट करना लिखा है तो वह पैसे पाना नहीं है।",
            ],
        },
        "hinglish": {
            "answer": "UPI collect scam mein fraudster refund, prize ya paise milne ke bahane aapse payment request approve karwata hai. Agar aap use approve karke UPI PIN daalte hain to paise aapke account mein aane ke bajay nikal jaate hain. Example ke liye, saaman bechte waqt koi buyer kehta hai ‘payment pane ke liye ye request approve karein’, jabki wo request asal mein aapse paise maang rahi hoti hai. Paise receive karne ke liye na UPI PIN ki zaroorat hoti hai, na kisi request ko approve karne ki.",
            "steps": [
                "Paise receive karne ke liye kabhi UPI PIN na daalein.",
                "Unknown logon ki collect request decline karein.",
                "Request apni UPI app mein padhein: agar usme aapko payment karna likha hai to wo paise milna nahi hai.",
            ],
        },
    },
    "link": {
        "en": {
            "answer": "A phishing link scam uses a fake website or misleading link to steal your login details, OTP, card data or money. A message that names your bank or a delivery company does not prove the link is genuine, because the visible name can be copied. For example, a text about a failed delivery can lead to a lookalike page that asks for your card number. Check the web address carefully, and open the official website or app yourself instead.",
            "steps": [
                "Do not tap links in unexpected messages; type the official address or use the official app.",
                "Look at the domain: lookalike spellings and odd endings are warning signs.",
                "Never enter an OTP, PIN or card details on a page you reached from a message link.",
            ],
        },
        "hi": {
            "answer": "फिशिंग लिंक स्कैम में नकली वेबसाइट या भ्रमित करने वाले लिंक से आपका लॉगिन, ओटीपी, कार्ड की जानकारी या पैसे चुराए जाते हैं। संदेश में बैंक या कूरियर कंपनी का नाम होने से लिंक असली साबित नहीं होता, क्योंकि दिखने वाला नाम कॉपी किया जा सकता है। उदाहरण के लिए, डिलीवरी फेल होने का मैसेज आपको ऐसे नकली पेज पर ले जा सकता है जो कार्ड नंबर माँगता है। वेब पता ध्यान से देखें और उसकी जगह आधिकारिक वेबसाइट या ऐप खुद खोलें।",
            "steps": [
                "अनचाहे संदेश के लिंक पर टैप न करें; आधिकारिक पता टाइप करें या आधिकारिक ऐप इस्तेमाल करें।",
                "डोमेन देखें: मिलते-जुलते स्पेलिंग और अजीब अंत चेतावनी के संकेत हैं।",
                "संदेश के लिंक से खुले पेज पर ओटीपी, पिन या कार्ड की जानकारी कभी न डालें।",
            ],
        },
        "hinglish": {
            "answer": "Phishing link scam mein fake website ya misleading link se aapka login, OTP, card details ya paise churaaye jaate hain. Message mein bank ya courier company ka naam hone se link asli sabit nahi hota, kyunki dikhne wala naam copy kiya ja sakta hai. Example ke liye, delivery fail hone ka message aapko aise fake page par le ja sakta hai jo card number maangta hai. Web address dhyan se dekhein aur uski jagah official website ya app khud kholein.",
            "steps": [
                "Unexpected message ke link par tap na karein; official address type karein ya official app use karein.",
                "Domain dekhein: milte-julte spelling aur ajeeb ending warning signs hain.",
                "Message ke link se khule page par OTP, PIN ya card details kabhi na daalein.",
            ],
        },
    },
    "digital_arrest": {
        "en": {
            "answer": "A ‘digital arrest’ scam is a phone or video call in which someone posing as police, CBI or customs says you are under arrest and must stay on the call and pay money. ‘Digital arrest’ is not a real legal process, and genuine agencies do not arrest people over a call or ask for money to close a case. For example, a caller may claim a parcel in your name contained illegal items. Hang up, do not transfer money, and report it.",
            "steps": [
                "End the call; no agency can arrest you over video or phone.",
                "Do not transfer money or share documents, OTPs or your screen.",
                "Report it on 1930 or at cybercrime.gov.in, and tell a family member.",
            ],
        },
        "hi": {
            "answer": "‘डिजिटल अरेस्ट’ स्कैम में पुलिस, सीबीआई या कस्टम अधिकारी बनकर कोई फ़ोन या वीडियो कॉल पर कहता है कि आप गिरफ़्तार हैं, कॉल पर बने रहें और पैसे भेजें। ‘डिजिटल अरेस्ट’ कोई वैध कानूनी प्रक्रिया नहीं है, और असली एजेंसियाँ कॉल पर गिरफ़्तारी नहीं करतीं और केस बंद करने के लिए पैसे नहीं माँगतीं। उदाहरण के लिए, कॉल करने वाला कह सकता है कि आपके नाम के पार्सल में गैरकानूनी सामान मिला है। कॉल काटें, पैसे ट्रांसफर न करें और शिकायत करें।",
            "steps": [
                "कॉल काट दें; कोई भी एजेंसी वीडियो या फ़ोन पर आपको गिरफ़्तार नहीं कर सकती।",
                "पैसे ट्रांसफर न करें और दस्तावेज़, ओटीपी या अपनी स्क्रीन साझा न करें।",
                "1930 पर या cybercrime.gov.in पर शिकायत करें, और परिवार के किसी सदस्य को बताएँ।",
            ],
        },
        "hinglish": {
            "answer": "‘Digital arrest’ scam mein police, CBI ya customs officer ban kar koi phone ya video call par kehta hai ki aap arrest hain, call par bane rahein aur paise bhejein. ‘Digital arrest’ koi real legal process nahi hai, aur asli agencies call par arrest nahi karti aur case close karne ke liye paise nahi maangti. Example ke liye, caller keh sakta hai ki aapke naam ke parcel mein illegal saaman mila hai. Call kaatein, paise transfer na karein aur report karein.",
            "steps": [
                "Call kaat dein; koi bhi agency video ya phone par aapko arrest nahi kar sakti.",
                "Paise transfer na karein aur documents, OTP ya apni screen share na karein.",
                "1930 par ya cybercrime.gov.in par report karein, aur family ke kisi member ko batayein.",
            ],
        },
    },
    "kyc": {
        "en": {
            "answer": "A KYC scam is a message or call claiming your bank account, SIM or wallet will be blocked unless you update KYC right now, usually through a link or by sharing an OTP. Real banks do not ask you to complete KYC by sending a code or clicking a link in a text. For example, an SMS says ‘KYC expires today, click here’, and the page steals your login. Update KYC only by visiting your branch or using the bank’s official app.",
            "steps": [
                "Do not click the link or share any OTP, Aadhaar or card details.",
                "Open your bank’s official app, or visit the branch, to check whether KYC is really pending.",
                "Tell your bank about the message, and report on 1930 or cybercrime.gov.in if you lost money.",
            ],
        },
        "hi": {
            "answer": "KYC स्कैम में संदेश या कॉल कहता है कि अभी केवाईसी अपडेट नहीं किया तो आपका बैंक खाता, सिम या वॉलेट बंद हो जाएगा, और इसके लिए लिंक खोलने या ओटीपी बताने को कहा जाता है। असली बैंक टेक्स्ट में लिंक या कोड भेजकर केवाईसी पूरा करने को नहीं कहते। उदाहरण के लिए, एसएमएस आता है ‘आज केवाईसी खत्म, यहाँ क्लिक करें’, और वह पेज आपका लॉगिन चुरा लेता है। केवाईसी सिर्फ़ शाखा जाकर या बैंक के आधिकारिक ऐप से अपडेट करें।",
            "steps": [
                "लिंक न खोलें और कोई ओटीपी, आधार या कार्ड की जानकारी न बताएँ।",
                "बैंक का आधिकारिक ऐप खोलें या शाखा जाकर देखें कि केवाईसी सच में बाकी है या नहीं।",
                "संदेश की जानकारी अपने बैंक को दें, और पैसे गए हों तो 1930 या cybercrime.gov.in पर शिकायत करें।",
            ],
        },
        "hinglish": {
            "answer": "KYC scam mein message ya call kehta hai ki abhi KYC update nahi kiya to aapka bank account, SIM ya wallet block ho jayega, aur iske liye link kholne ya OTP batane ko kaha jaata hai. Asli bank text mein link ya code bhejkar KYC poora karne ko nahi kehte. Example ke liye, SMS aata hai ‘aaj KYC expire, yahan click karein’, aur wo page aapka login chura leta hai. KYC sirf branch jakar ya bank ki official app se update karein.",
            "steps": [
                "Link na kholein aur koi OTP, Aadhaar ya card details na batayein.",
                "Bank ki official app kholein ya branch jakar dekhein ki KYC sach mein pending hai ya nahi.",
                "Message ki jaankari apne bank ko dein, aur paise gaye hon to 1930 ya cybercrime.gov.in par report karein.",
            ],
        },
    },
    "job": {
        "en": {
            "answer": "A job or task scam offers easy money for liking videos, writing reviews or finishing simple tasks, then asks you to deposit money to unlock higher earnings. Small early payouts are used to build trust before you are asked to send larger amounts that you never get back. Genuine employers do not charge you to start work or ask for deposits. Check the company independently before you share documents or money.",
            "steps": [
                "Do not pay any deposit, registration fee or recharge to start a job or task.",
                "Verify the company on its official website and through independent reviews.",
                "Stop contact, keep screenshots, and report on 1930 or cybercrime.gov.in if you paid.",
            ],
        },
        "hi": {
            "answer": "नौकरी या टास्क स्कैम में वीडियो लाइक करने, रिव्यू लिखने या आसान टास्क पूरे करने पर आसान कमाई का ऑफर दिया जाता है, फिर ज़्यादा कमाई अनलॉक करने के लिए पैसे जमा करने को कहा जाता है। शुरू में छोटे भुगतान देकर भरोसा बनाया जाता है, फिर बड़ी रकम माँगी जाती है जो कभी वापस नहीं मिलती। असली नियोक्ता काम शुरू करने के लिए पैसे नहीं लेते और डिपॉज़िट नहीं माँगते। दस्तावेज़ या पैसे देने से पहले कंपनी की स्वतंत्र रूप से जाँच करें।",
            "steps": [
                "नौकरी या टास्क शुरू करने के लिए कोई डिपॉज़िट, रजिस्ट्रेशन फीस या रिचार्ज न दें।",
                "कंपनी की आधिकारिक वेबसाइट और स्वतंत्र रिव्यू से उसकी पुष्टि करें।",
                "संपर्क बंद करें, स्क्रीनशॉट रखें, और पैसे दे चुके हों तो 1930 या cybercrime.gov.in पर शिकायत करें।",
            ],
        },
        "hinglish": {
            "answer": "Job ya task scam mein videos like karne, review likhne ya aasan tasks poore karne par easy earning ka offer diya jaata hai, phir zyada earning unlock karne ke liye paise deposit karne ko kaha jaata hai. Shuru mein chhote payout dekar trust banaya jaata hai, phir badi rakam maangi jaati hai jo kabhi wapas nahi milti. Asli employer kaam shuru karne ke liye paise nahi lete aur deposit nahi maangte. Documents ya paise dene se pehle company ko independently verify karein.",
            "steps": [
                "Job ya task shuru karne ke liye koi deposit, registration fee ya recharge na dein.",
                "Company ko official website aur independent reviews se verify karein.",
                "Contact band karein, screenshots rakhein, aur paise de chuke hon to 1930 ya cybercrime.gov.in par report karein.",
            ],
        },
    },
    "spot_scam": {
        "en": {
            "answer": "Most scam messages share the same few warning signs: they create urgency (‘today’, ‘immediately’, ‘account will be blocked’), claim to be a bank, government office or delivery company, offer a prize or easy money, or ask for an OTP, PIN, password or a payment. A link you did not expect is another sign. For example, a text saying your account will be blocked unless you click a link now is a classic pattern. None of these signs is proof on its own, so verify the sender through an official app or website you open yourself.",
            "steps": [
                "Look for pressure: a deadline, a threat, or a ‘last chance’ wording.",
                "Check what it asks for: an OTP, PIN, password, fee or a link click is a red flag.",
                "Verify through the official app, website or the number on your card, not through the message.",
            ],
        },
        "hi": {
            "answer": "ज़्यादातर स्कैम संदेशों में कुछ एक जैसे संकेत होते हैं: जल्दबाज़ी का दबाव (‘आज ही’, ‘तुरंत’, ‘खाता बंद हो जाएगा’), बैंक, सरकारी विभाग या कूरियर कंपनी होने का दावा, इनाम या आसान कमाई का लालच, या ओटीपी, पिन, पासवर्ड या पैसे की माँग। अनचाहा लिंक भी एक संकेत है। उदाहरण के लिए, ‘अभी लिंक पर क्लिक करें वरना खाता बंद’ वाला संदेश एक पुराना तरीका है। इनमें से कोई एक संकेत अकेले सबूत नहीं है, इसलिए आधिकारिक ऐप या वेबसाइट खुद खोलकर भेजने वाले की पुष्टि करें।",
            "steps": [
                "दबाव देखें: समय सीमा, धमकी या ‘आखिरी मौका’ जैसे शब्द।",
                "देखें कि क्या माँगा जा रहा है: ओटीपी, पिन, पासवर्ड, फीस या लिंक पर क्लिक खतरे का संकेत है।",
                "पुष्टि संदेश से नहीं, आधिकारिक ऐप, वेबसाइट या कार्ड पर छपे नंबर से करें।",
            ],
        },
        "hinglish": {
            "answer": "Zyaadatar scam messages mein kuch ek jaise warning signs hote hain: jaldbaazi ka pressure (‘aaj hi’, ‘turant’, ‘account band ho jayega’), bank, sarkari office ya courier company hone ka daava, prize ya aasaan kamaai ka laalach, ya OTP, PIN, password ya paise ki demand. Unexpected link bhi ek sign hai. Example ke liye, ‘abhi link par click karo warna account band’ wala message ek purana tareeka hai. In mein se koi ek sign akela saboot nahi hai, isliye official app ya website khud kholkar sender ko verify karein.",
            "steps": [
                "Pressure dekhein: deadline, dhamki ya ‘last chance’ jaise shabd.",
                "Dekhein ki kya maanga ja raha hai: OTP, PIN, password, fee ya link par click red flag hai.",
                "Verify message se nahi, official app, website ya card par chhape number se karein.",
            ],
        },
    },
    "general": {
        "en": {
            "answer": "Online scams use pressure, fake authority, tempting rewards or requests for sensitive details to get your money or account access. Common examples in India are fake bank or KYC alerts, UPI collect requests, courier and prize messages, and ‘digital arrest’ calls. The safest habit is to pause, then verify the request yourself through an official app, website or the number on your card. Never share an OTP, UPI PIN, CVV or password with anyone.",
            "steps": [
                "Pause and verify the sender through an official app, website or a number you found yourself.",
                "Never share an OTP, UPI PIN, CVV or password, and never pay a fee to receive money or a prize.",
                "If money is lost, call 1930 immediately and report at cybercrime.gov.in.",
            ],
        },
        "hi": {
            "answer": "ऑनलाइन स्कैम में दबाव, नकली अधिकारी, लुभावने इनाम या संवेदनशील जानकारी की माँग से आपके पैसे या खाते तक पहुँचने की कोशिश होती है। भारत में आम उदाहरण हैं: नकली बैंक या केवाईसी अलर्ट, UPI कलेक्ट रिक्वेस्ट, कूरियर और इनाम के संदेश, और ‘डिजिटल अरेस्ट’ कॉल। सबसे सुरक्षित आदत है रुकना, फिर आधिकारिक ऐप, वेबसाइट या कार्ड पर छपे नंबर से खुद पुष्टि करना। ओटीपी, UPI पिन, CVV या पासवर्ड किसी को न बताएँ।",
            "steps": [
                "रुकें और भेजने वाले की पुष्टि आधिकारिक ऐप, वेबसाइट या खुद खोजे हुए नंबर से करें।",
                "ओटीपी, UPI पिन, CVV या पासवर्ड कभी न बताएँ, और पैसे या इनाम पाने के लिए फीस न दें।",
                "पैसे चले गए हों तो तुरंत 1930 पर कॉल करें और cybercrime.gov.in पर शिकायत करें।",
            ],
        },
        "hinglish": {
            "answer": "Online scams mein pressure, fake authority, lubhaavne rewards ya sensitive details ki demand se aapke paise ya account tak pahunchne ki koshish hoti hai. India mein aam examples hain: fake bank ya KYC alerts, UPI collect requests, courier aur prize messages, aur ‘digital arrest’ calls. Sabse safe aadat hai rukna, phir official app, website ya card par chhape number se khud verify karna. OTP, UPI PIN, CVV ya password kisi ko na batayein.",
            "steps": [
                "Ruk kar sender ko official app, website ya khud dhoondhe hue number se verify karein.",
                "OTP, UPI PIN, CVV ya password kabhi na batayein, aur paise ya prize paane ke liye fee na dein.",
                "Paise chale gaye hon to turant 1930 par call karein aur cybercrime.gov.in par report karein.",
            ],
        },
    },
}

# Checked in order; the first match wins. "shared_otp" must come first so that
# "I accidentally shared my OTP" is not answered with the generic OTP topic.
TOPIC_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "shared_otp",
        re.compile(
            r"(?:\b(?:shared|gave|told|sent|read out|disclosed|leaked)\b.{0,40}\b(?:otp|pin|password|cvv)\b"
            r"|\b(?:otp|pin|password|cvv)\b.{0,40}\b(?:shared|given|told|sent|leaked|disclosed)\b"
            r"|\b(?:accidentally|by mistake|galti se|ghalti se)\b.{0,40}\b(?:otp|pin|password|cvv)\b"
            r"|\b(?:otp|pin|password|cvv)\b.{0,40}\b(?:bata diya|bata di|share kar diya|share kar di|bhej diya|bhej di|de diya|de di|galti se)\b"
            r"|(?:ओटीपी|पिन|पासवर्ड).{0,40}(?:बता दिया|बता दी|शेयर कर दिया|भेज दिया|दे दिया|दे दी|गलती से)"
            r"|गलती से.{0,40}(?:ओटीपी|पिन|पासवर्ड))",
            re.IGNORECASE,
        ),
    ),
    ("digital_arrest", re.compile(r"digital arrest|डिजिटल अरेस्ट|giraftari", re.IGNORECASE)),
    ("upi", re.compile(r"\bupi\b|collect request|यूपीआई|कलेक्ट", re.IGNORECASE)),
    ("kyc", re.compile(r"\bkyc\b|केवाईसी", re.IGNORECASE)),
    ("email", re.compile(r"\be-?mail\b|\bmail\b|ईमेल", re.IGNORECASE)),
    ("otp", re.compile(r"\botp\b|one.?time (?:password|code)|ओटीपी", re.IGNORECASE)),
    (
        "link",
        re.compile(r"\b(?:link|url|phishing|website|fake site|qr)\b|लिंक|फिशिंग|वेबसाइट", re.IGNORECASE),
    ),
    (
        "job",
        re.compile(r"\b(?:job|task|work from home|part.?time|naukri)\b|नौकरी|जॉब|टास्क", re.IGNORECASE),
    ),
    (
        "spot_scam",
        re.compile(
            r"\b(?:scams?|fraud|fake|suspicious|dhokh\w*|thag\w*|thagi|jaal\w*)\b"
            r"|\b(?:pehchan\w*|pahchan\w*|samajh\w*|samjh\w*|identify|recogni[sz]e|spot)\b"
            r"|धोख|ठग|स्कैम|फर्जी|नकली|पहचान|समझ",
            re.IGNORECASE,
        ),
    ),
]


def detect_topic(message: str) -> str:
    """Pick the knowledge-base topic that best matches a scam question."""
    for topic, pattern in TOPIC_PATTERNS:
        if pattern.search(message or ""):
            return topic
    return "general"


# Shown beside a report when the person says the sender is a stranger. It is
# context, not a score: who sent a message is not visible in its text.
SENDER_UNKNOWN: dict[str, dict] = {
    "en": {
        "title": "This message is from someone you don't know",
        "text": "A stranger's message is not a scam by itself, and this check can only read the text, not see who sent it. Scammers often open with a friendly or ‘wrong number’ message and only later ask for money, a code or a click.",
        "steps": [
            "Do not reply with personal details, and do not click links or send money.",
            "Confirm who it is through a contact you already trust or an official number.",
            "If it turns into a request for money, stop and report at cybercrime.gov.in or call 1930.",
        ],
    },
    "hi": {
        "title": "यह संदेश किसी अनजान व्यक्ति का है",
        "text": "अनजान व्यक्ति का संदेश अपने आप में स्कैम नहीं होता, और यह जाँच सिर्फ़ टेक्स्ट पढ़ सकती है, भेजने वाले को नहीं देख सकती। ठग अक्सर दोस्ताना या ‘गलत नंबर’ वाले संदेश से शुरू करते हैं और बाद में पैसे, कोड या क्लिक माँगते हैं।",
        "steps": [
            "निजी जानकारी देकर जवाब न दें, लिंक पर क्लिक न करें और पैसे न भेजें।",
            "पहले किसी भरोसेमंद संपर्क या आधिकारिक नंबर से पुष्टि करें कि यह कौन है।",
            "पैसे की माँग शुरू हो तो रुकें, cybercrime.gov.in पर शिकायत करें या 1930 पर कॉल करें।",
        ],
    },
    "hinglish": {
        "title": "Ye message kisi anjaan insaan ka hai",
        "text": "Anjaan insaan ka message apne aap mein scam nahi hota, aur ye check sirf text padh sakta hai, bhejne waale ko nahi dekh sakta. Thag aksar dosti bhare ya ‘wrong number’ message se shuru karte hain aur baad mein paise, code ya click maangte hain.",
        "steps": [
            "Personal details dekar reply na karein, link par click na karein aur paise na bhejein.",
            "Pehle kisi bharosemand contact ya official number se confirm karein ki ye kaun hai.",
            "Paise ki maang shuru ho to ruken, cybercrime.gov.in par report karein ya 1930 par call karein.",
        ],
    },
}
