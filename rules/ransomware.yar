rule WannaCry_Ransomware {
    meta:
        description = "Detects WannaCry ransomware characteristics"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $string1 = "WANACRY" nocase
        $string2 = "@WanaDecryptor" nocase
        $string3 = "tor/" nocase
        $api1 = "CryptEncrypt" ascii
        $api2 = "CryptDecrypt" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Petya_Ransomware {
    meta:
        description = "Detects Petya/NotPetya ransomware characteristics"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $string1 = "petya" nocase
        $string2 = "notpetya" nocase
        $string3 = "disk" nocase
        $api1 = "CreateFileA" ascii
        $api2 = "WriteFile" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Locky_Ransomware {
    meta:
        description = "Detects Locky ransomware characteristics"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $string1 = "locky" nocase
        $string2 = ".locky" nocase
        $string3 = "decrypt" nocase
        $api1 = "CryptEncrypt" ascii
        $api2 = "CryptGenKey" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Cerber_Ransomware {
    meta:
        description = "Detects Cerber ransomware characteristics"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $string1 = "cerber" nocase
        $string2 = ".cerber" nocase
        $string3 = "decrypt" nocase
        $api1 = "CryptEncrypt" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule GandCrab_Ransomware {
    meta:
        description = "Detects GandCrab ransomware characteristics"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $string1 = "gandcrab" nocase
        $string2 = "ransom" nocase
        $api1 = "CryptEncrypt" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Ryuk_Ransomware {
    meta:
        description = "Detects Ryuk ransomware characteristics"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $string1 = "ryuk" nocase
        $string2 = "ransom" nocase
        $api1 = "CryptEncrypt" ascii
        $api2 = "CreateFileA" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Maze_Ransomware {
    meta:
        description = "Detects Maze ransomware characteristics"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $string1 = "maze" nocase
        $string2 = "decrypt" nocase
        $api1 = "CryptEncrypt" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
