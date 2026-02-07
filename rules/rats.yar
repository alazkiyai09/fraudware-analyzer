rule PoisonIvy_RAT {
    meta:
        description = "Detects Poison Ivy Remote Access Trojan"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $string1 = "PoisonIvy" nocase
        $string2 = "PI_" nocase
        $api1 = "InternetOpenA" ascii
        $api2 = "HttpSendRequestA" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Gh0st_RAT {
    meta:
        description = "Detects Gh0st Remote Access Trojan"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $string1 = "gh0st" nocase
        $string2 = "ghost" nocase
        $api1 = "InternetOpenA" ascii
        $api2 = "CreateProcessA" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule DarkComet_RAT {
    meta:
        description = "Detects DarkComet Remote Access Trojan"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $string1 = "DarkComet" nocase
        $string2 = "darkcomet" nocase
        $api1 = "InternetOpenA" ascii
        $api2 = "CreateProcessA" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule njRAT_RAT {
    meta:
        description = "Detects njRAT Remote Access Trojan"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $string1 = "njrat" nocase
        $string2 = "njrat" nocase
        $string3 = "njr" nocase
        $api1 = "InternetOpenA" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule XtremeRAT_RAT {
    meta:
        description = "Detects XtremeRAT Remote Access Trojan"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $string1 = "xtremerat" nocase
        $string2 = "xtreme" nocase
        $api1 = "InternetOpenA" ascii
        $api2 = "CreateProcessA" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
