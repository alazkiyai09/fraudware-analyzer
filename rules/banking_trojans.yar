rule Zeus_Banking_Trojan {
    meta:
        description = "Detects Zeus/Zbot banking trojan characteristics"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $config1 = "software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" nocase
        $api1 = "InternetOpenA" ascii
        $api2 = "HttpSendRequestA" ascii
        $api3 = "InternetConnectA" ascii
        $api4 = "GetAsyncKeyState" ascii
        $string1 = "httpsendrequest" nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule SpyEye_Banking_Trojan {
    meta:
        description = "Detects SpyEye banking trojan characteristics"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $api1 = "InternetOpenA" ascii
        $api2 = "HttpSendRequestA" ascii
        $api3 = "GetClipboardData" ascii
        $string1 = "spyeye" nocase
        $string2 = "wininet.dll" nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Carberp_Banking_Trojan {
    meta:
        description = "Detects Carberp banking trojan characteristics"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $api1 = "CreateProcessA" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "VirtualAllocEx" ascii
        $string1 = "carberp" nocase
        $string2 = "\\Registry\\Machine\\Software" nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Citadel_Banking_Trojan {
    meta:
        description = "Detects Citadel banking trojan characteristics"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $api1 = "InternetOpenA" ascii
        $api2 = "InternetConnectA" ascii
        $api3 = "HttpSendRequestA" ascii
        $string1 = "citadel" nocase
        $string2 = "wininet" nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Dyre_Banking_Trojan {
    meta:
        description = "Detects Dyre banking trojan characteristics"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $api1 = "InternetOpenA" ascii
        $api2 = "HttpSendRequestA" ascii
        $string1 = "dyre" nocase
        $string2 = "dyreza" nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Dridex_Banking_Trojan {
    meta:
        description = "Detects Dridex banking trojan characteristics"
        author = "Fraudware Analyzer"
        date = "2024"
    strings:
        $api1 = "InternetOpenA" ascii
        $api2 = "HttpSendRequestA" ascii
        $string1 = "dridex" nocase
        $string2 = "loader" nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
