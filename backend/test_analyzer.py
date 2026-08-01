from analyzer import analyze_email

SAFE_EMAIL = """From: Alex Chen <alex.chen@company.com>
Subject: Lunch tomorrow?

Hey, are you free for lunch tomorrow around noon? Let me know what works.

Alex
"""

PHISHING_EMAIL = """From: PayPal Security <support@paypa1-verify.com>
Subject: URGENT!! Your Account Will Be Suspended

Dear Customer,

We have detected UNUSUAL ACTIVITY on your account. You must verify your
identity immediately or your account will be suspended within 24 hours.

Click here to confirm your password: http://bit.ly/paypal-verify-acct

PayPal Security Team!!!
"""


def test_safe_email_scores_low():
    result = analyze_email(SAFE_EMAIL)
    assert result["score"] < 25
    assert result["verdict"] == "Likely Safe"


def test_phishing_email_scores_high():
    result = analyze_email(PHISHING_EMAIL)
    assert result["score"] >= 55
    assert result["verdict"] == "Potential Phishing"
    tags = {f["tag"] for f in result["findings"]}
    assert "SHORTENED LINK" in tags
    assert "URGENCY" in tags
    assert "SENSITIVE REQUEST" in tags


if __name__ == "__main__":
    test_safe_email_scores_low()
    test_phishing_email_scores_high()
    print("All tests passed.")
