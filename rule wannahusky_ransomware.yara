rule wannahusky_ransomware {
    
    meta: 
        last_updated = "2023-03-23"
        author = "finx"
        description = "YARA rule to detect Wannahusky Ransomware"

    strings:
        // Fill out identifying strings and other criteria
        $PE_magic_byte = "MZ"
        $string1 = "nim" ascii
        $string2 = "WANNAHUSKY.png" ascii
        $string3 = "cosmo.WANNAHUSKY" ascii
        $string4 = "ps1.ps1" ascii
        

    condition:
        // Fill out the conditions that must be met to identify the binary
        $PE_magic_byte at 0 and 
        all of them

}

