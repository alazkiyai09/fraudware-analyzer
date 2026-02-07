rule Pony_Stealer {
    meta:
        description = "Detects Pony information stealer"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $api1 = "GetClipboardData" ascii
        $api2 = "InternetOpenA" ascii
        $string1 = "pony" nocase
        $string2 = "password" nocase
        $string3 = "ftp://" nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Fareit_Stealer {
    meta:
        description = "Detects Fareit information stealer"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $api1 = "InternetOpenA" ascii
        $api2 = "CryptDecrypt" ascii
        $string1 = "fareit" nocase
        $string2 = "password" nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule LokiBot_Stealer {
    meta:
        description = "Detects LokiBot information stealer"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $api1 = "InternetOpenA" ascii
        $api2 = "HttpSendRequestA" ascii
        $string1 = "lokibot" nocase
        $string2 = "loki" nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Azorult_Stealer {
    meta:
        description = "Detects Azorult information stealer"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $api1 = "InternetOpenA" ascii
        $string1 = "azorult" nocase
        $string2 = "bitcoin" nocase
    condition:
        uint16(0) == 0x5A4D and 1 of them
}

rule RedLine_Stealer {
    meta:
        description = "Detects RedLine information stealer"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $api1 = "InternetOpenA" ascii
        $string1 = "redline" nocase
        $string2 = "stealer" nocase
    condition:
        uint16(0) == 0x5A4D and 1 of them
}

rule Raccoon_Stealer {
    meta:
        description = "Detects Raccoon information stealer"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $api1 = "InternetOpenA" ascii
        $string1 = "raccoon" nocase
        $string2 = "stealer" nocase
    condition:
        uint16(0) == 0x5A4D and 1 of them
}
