Function Get-SPFRecord {
    Param(
        $DNS
    )
    $SPFRecords = $((Resolve-DnsName -Name $DNS -Type txt -ErrorAction Stop | Where-Object Strings -Match "spf1").Strings).Split(", ") | Where-Object {$_}

    $SPFRecord = @()

    # Record the SPF Version
    $SPFRecord += [PSCustomObject] @{
        Prefix      = ''
        Type        = $SPFRecords[0].split("=")[0]
        Value       = $SPFRecords[0].split("=")[1]
        PrefixDesc  = ''
        Description = 'The SPF record version.'
    }

    ForEach($Record in $SPFRecords ){
        If($Record -like "*:*"){

            $SPFType        = $Record.Split(":")[0]
            $SPFValue       = $Record.Split(":")[1]
            $SPFDescription = ""

            # SPF Record type descriptions provided by Google (https://support.google.com/a/answer/10683907)
            Switch ($SPFType) {
                "ip4"     {$SPFDescription = "Authorize mail servers by IPv4 address or address range. "}
                "ip6"     {$SPFDescription = "Authorize mail servers by IPv6 address or address range."}
                "a"       {$SPFDescription = "Authorize mail servers by domain name."}
                "mx"      {$SPFDescription = "Authorize one or more mail servers by domain MX record."}
                "include" {$SPFDescription = "Authorize third-party email senders by domain."}
                default { "Invalid SPF Record Type" }
            }

            $SPFRecord += [PSCustomObject] @{
                Prefix      = '+'
                Type        = $SPFType
                Value       = $SPFValue
                PrefixDesc  = 'Pass'
                Description = $SPFDescription
            }
        }
    }

    # Record the SPF Qualifier
    Switch ($SPFRecords[$SPFRecords.Count - 1].Substring(0,1)) {
        "+" {$SPFQualifier = "Pass"}
        "-" {$SPFQualifier = "Fail"}
        "~" {$SPFQualifier = "Soft Fail"}
        "?" {$SPFQualifier = "Neutral"}
        default { "Invalid qualifier" }
    }

    $SPFRecord += [PSCustomObject] @{
        Prefix      = $SPFRecords[$SPFRecords.Count - 1].Substring(0,1)
        Type        = $SPFRecords[$SPFRecords.Count - 1].Substring(1)
        Value       = ''
        PrefixDesc  = $SPFQualifier
        Description = 'Specifies that all incoming messages match.'
    }

    $SPFRecord | Format-Table
}
