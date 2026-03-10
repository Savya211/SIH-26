# Feature configuration for TheThirdEye ML model
# Maps PhiUSIIL dataset columns to browser-extracted signals

# All numerical feature columns from PhiUSIIL (drop text cols: URL, Domain, TLD, Title)
FEATURE_COLUMNS = [
    "URLLength", "DomainLength", "IsDomainIP", "URLSimilarityIndex",
    "CharContinuationRate", "TLDLegitimateProb", "URLCharProb", "TLDLength",
    "NoOfSubDomain", "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio",
    "NoOfLettersInURL", "LetterRatioInURL", "NoOfDegitsInURL", "DegitRatioInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL",
    "IsHTTPS", "LineOfCode", "LargestLineLength", "HasTitle",
    "DomainTitleMatchScore", "URLTitleMatchScore", "HasFavicon", "Robots",
    "IsResponsive", "NoOfURLRedirect", "NoOfSelfRedirect", "HasDescription",
    "NoOfPopup", "NoOfiFrame", "HasExternalFormSubmit", "HasSocialNet",
    "HasSubmitButton", "HasHiddenFields", "HasPasswordField",
    "Bank", "Pay", "Crypto", "HasCopyrightInfo",
    "NoOfImage", "NoOfCSS", "NoOfJS", "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef",
]

# Text columns to drop during training
TEXT_COLUMNS = ["URL", "Domain", "TLD", "Title"]

# Target column
TARGET_COLUMN = "label"

# Mapping from page-analyzer.js signals to PhiUSIIL features
# Signal names match what background/service-worker.js sends to the backend
SIGNAL_TO_FEATURE = {
    # Directly mappable
    "isHTTPS":          "IsHTTPS",
    "passwordFields":   "HasPasswordField",   # > 0 → 1
    "hiddenIframes":    "NoOfiFrame",
    "externalScripts":  "NoOfJS",
    "redirectCount":    "NoOfURLRedirect",
    "creditCardFields": "Pay",                # > 0 → 1
    "totalForms":       "HasSubmitButton",    # > 0 → 1
    "popupCount":       "NoOfPopup",
}

# Suspicious keywords that hint at phishing categories
BANK_KEYWORDS = ["bank", "banking", "login", "signin", "account", "secure"]
PAY_KEYWORDS  = ["payment", "pay", "checkout", "billing", "credit", "card"]
CRYPTO_KEYWORDS = ["crypto", "bitcoin", "wallet", "btc", "eth", "nft"]
