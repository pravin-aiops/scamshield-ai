# Generated from evaluation corpora: scams must not score Low, genuine messages must.
import pytest
from backend.app.detector import analyze_message

SCAMS = [
 "Dear user your SIM will be blocked in 2 hours. Call 9876543210 now to complete KYC verification.",
 "Congratulations! You are pre-approved for a Rs 5,00,000 personal loan. Pay Rs 1,999 processing fee to release the amount.",
 "Income Tax Dept: You have a refund of Rs 15,490 pending. Verify your bank account at incometax-refund.in to receive it.",
 "Your Aadhaar will be deactivated. Update now at aadhaar-update.co.in or lose access to all services.",
 "PAN card not linked with Aadhaar. Your account will be frozen today. Click http://pan-link.top to link.",
 "FASTag wallet balance low. Recharge now at fastag-recharge.xyz or your tag will be blacklisted.",
 "Traffic challan of Rs 500 issued on your vehicle. Pay within 24 hours at echallan-pay.net to avoid court notice.",
 "KBC Lottery Winner! You have won Rs 25,00,000. Contact Mr. Rana on WhatsApp +92 300 1234567 to claim prize.",
 "Hi, I accidentally sent Rs 20,000 to your number. Please return it urgently, I am in hospital.",
 "Download AnyDesk and share the 9 digit code so our executive can fix your refund issue.",
 "I am interested in buying your sofa on OLX. I have sent a QR code, scan it to receive the advance payment.",
 "Urgent hiring in Dubai, salary 80000. Pay Rs 15000 visa processing fee to confirm your offer letter.",
 "Invest Rs 10,000 in our crypto plan and get Rs 50,000 in 7 days. Guaranteed returns. Join our Telegram group now.",
 "Exclusive stock tips group. 300% profit guaranteed this week. Join WhatsApp group and pay Rs 999 membership.",
 "Amazon: Your order refund of Rs 3,299 failed. Confirm your card number and CVV at amazon-refund-help.com.",
 "Netflix: Your payment failed and account will be suspended. Update your card details at netflix-billing-update.com now.",
 "Your electricity meter KYC is pending. Call 8800123456 immediately or power will be cut tonight.",
 "Your Paytm KYC has expired. Account will be blocked. Send your PAN and Aadhaar photo on WhatsApp 9123456780.",
 "Dear customer your debit card is blocked. To unblock share the card number, expiry date and the OTP you receive.",
 "Customs has seized a gift parcel for you from UK. Pay Rs 25,000 clearance charges to receive it.",
 "Your video call recording has been captured. Pay Rs 50,000 or we will send it to all your contacts.",
 "Mom I lost my phone, this is my new number. Please send Rs 15000 urgently to this account, will explain later.",
 "EPFO: Your PF claim of Rs 82,000 is approved. Verify your bank details at epfo-claim.in to receive money.",
 "Sir, I am calling from SBI. Your credit card limit has been increased. Share the OTP to activate the new limit.",
 "आपका बैंक खाता आज बंद हो जाएगा। तुरंत लिंक पर क्लिक करके केवाईसी अपडेट करें।",
 "आपको 10 लाख की लॉटरी लगी है। इनाम पाने के लिए 5000 रुपये प्रोसेसिंग फीस जमा करें।",
 "Aapka SIM band hone wala hai. Turant is number par call karein aur apna Aadhaar number batayein.",
 "Bhai mujhe urgent Rs 10000 chahiye, abhi Google Pay kar de, kal wapas kar dunga. Mera account number ye hai.",
 "Aapka challan kat gaya hai. Aaj hi pay karein warna license cancel ho jayega: echallan-india.xyz",
 "Free Rs 500 Amazon voucher for first 100 users! Click now and enter your bank details to claim.",
 "Last warning: your courier is returned. Confirm address and pay Rs 30 redelivery fee: http://postal-redeliver.cc",
 "You have received a legal notice from the High Court. Call this number immediately or arrest warrant will be issued.",
 "Your WhatsApp will expire today. Verify your number with the 6 digit code we sent to keep your account.",
 "Work from home and earn Rs 3000 per day just by rating hotels on Google Maps. Contact us on Telegram @earnfast.",
 "Your LIC policy has lapsed. Pay Rs 4,500 today at lic-renew-now.in to restore benefits or lose bonus.",
 "Sir aapka Jio number 24 ghante me band ho jayega. Abhi 9811122233 par call karke KYC karein.",
 "Police case registered against your Aadhaar. Pay Rs 25,000 settlement immediately to avoid arrest.",
 "Work from home! Earn Rs 5000 daily by liking videos. Send Rs 500 registration fee to start.",
 "Dear customer, your credit card reward points worth Rs 8,000 expire today. Redeem now at card-rewards-hdfc.top",
 "Hi Mom, my phone broke, this is my new number. Please send Rs 30,000 to this account urgently, will explain later.",
 "आपका बैंक खाता आज बंद हो जाएगा। तुरंत आधार और ओटीपी भेजें।",
 "Congratulations you won a free iPhone 15. Pay Rs 299 delivery charges to claim now.",
 "Your parcel is held at customs. Pay Rs 1,850 clearance fee today to release it: http://cust-clear.top/pay",
 "Send me a photo of your debit card front and back and the 3 digit code, I will refund your money now.",
 "Final notice: your electricity connection will be cut tonight. Call 9988776655 immediately.",
 "Earn money by rating hotels on Google. Join our Telegram group and get Rs 150 per task, deposit Rs 1000 first."
]

GENUINE = [
 "Your OTP for login is 482913. Do not share it with anyone. Valid for 10 minutes.",
 "Rs 1,250 debited from A/c XX4821 on 20-Oct at Swiggy. Avl bal Rs 12,300. Not you? Call 1930 or visit your branch.",
 "Your Amazon order #402-1234 has been shipped and will arrive tomorrow by 8 PM.",
 "Hi, are we still meeting for lunch at 1 PM tomorrow? Let me know.",
 "Reminder: your dentist appointment is on Friday at 4:30 PM at Smile Clinic.",
 "Your electricity bill of Rs 1,240 for September is due on 25 Oct. Pay via the official app.",
 "Dear parent, school will remain closed tomorrow due to heavy rain. Regards, Principal.",
 "Your Jio recharge of Rs 299 is successful. Validity 28 days. Thank you.",
 "IRCTC: Your ticket PNR 4521896345 is confirmed for 22 Oct, Coach S4, Berth 32.",
 "Happy birthday! Wishing you a wonderful year ahead. Let's catch up this weekend.",
 "Your Zomato order is out for delivery. OTP for delivery is 4821. Share it only with the delivery partner.",
 "Mom: Please pick up milk and bread on the way home.",
 "HDFC Bank: Never share your OTP, PIN or CVV with anyone, even bank staff.",
 "Your salary of Rs 54,000 has been credited to your account on 30-Sep.",
 "Flipkart: Your refund of Rs 799 has been initiated and will reflect in 3-5 working days.",
 "Team meeting moved to 3 PM. Please join using the usual calendar link.",
 "Your gas cylinder booking is confirmed. Delivery tomorrow between 10 and 12.",
 "Bhai kal match dekhne chalna hai? Ticket maine book kar diye hain.",
 "Aapka Airtel bill Rs 499 generate ho gaya hai. Last date 5 Nov. My Airtel app se pay karein.",
 "Power cut scheduled in your area on Sunday 10 AM to 2 PM for maintenance.",
 "नमस्ते, कल शाम 6 बजे घर आना है। माँ ने खाना बनाया है।",
 "Your PhonePe payment of Rs 150 to Raju Tea Stall was successful.",
 "Congratulations on your promotion! Proud of you. Dinner on me this weekend.",
 "Your cab is arriving in 3 minutes. Driver Ramesh, KA01AB1234. Share OTP 5521 to start the trip.",
 "Dear customer, your credit card statement for Oct is ready. Min due Rs 500, due date 15 Nov. Download from the official app.",
 "Your OLX ad has received a new message. Open the OLX app to reply.",
 "Can you send me the project report by tonight? Thanks.",
 "I paid Rs 500 for the movie tickets, send me your half when free.",
 "LIC: Premium of Rs 4,200 is due on 12 Nov. Pay through the LIC app or nearest branch.",
 "Sale: Flat 30 percent off on shoes this weekend at Myntra. Shop in the app.",
 "Hi, are we still meeting at 6 pm today? Let me know.",
 "Your OTP for login is 483920. Do not share it with anyone.",
 "Your Swiggy order is out for delivery. Share OTP 4821 only with the delivery partner.",
 "HDFC Bank: Rs 2,300 debited from a/c XX1234 at Amazon on 12-Oct. If not you, call the number on your card.",
 "Reminder: your electricity bill of Rs 1,240 is due on 25th. Pay via the official app or website.",
 "Mom, I transferred Rs 5000 to your account, please check.",
 "Your Ola ride is arriving. Share OTP 5521 with the driver to start the trip.",
 "Meeting rescheduled to tomorrow 10 am. Please confirm.",
 "Your Amazon package will be delivered today by 8 pm.",
 "Beta, kal ghar aa raha hu, paise bhej diye hain apne account me check kar lena."
]


@pytest.mark.parametrize("text", SCAMS)
def test_scam_styles_are_not_low(text):
    assert analyze_message(text)["risk_level"] != "low"


@pytest.mark.parametrize("text", GENUINE)
def test_genuine_messages_stay_low(text):
    assert analyze_message(text)["risk_level"] == "low"
