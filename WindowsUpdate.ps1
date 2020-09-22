<#
    Windows Update Script
    Version 1.0-2020
#>

if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
}
else {
    Install-Module -Name PSWindowsUpdate -Confirm
}
Import-Module -Name PSWindowsUpdate
Import-Module -Name Microsoft.PowerShell.Management
$n = 0
$a = 0

#Function
Function UpdateFirefox {
$path = $env:temp
$computer = $env:COMPUTERNAME
$ErrorActionPreference = "Stop"
$start_time = Get-Date
$empty_line = ""
$quote ='"'
$unquote ='"'
$firefox_enumeration = @()
$latest_firefox = @()
$after_update_firefoxes = @()
Function Check-InstalledSoftware ($display_name) {
    Return Get-ItemProperty $registry_paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like $display_name }
}
If ([IntPtr]::Size -eq 8) {
    $empty_line | Out-String
    "Running in a 64-bit subsystem" | Out-String
    $64 = $true
    $bit_number = "64"
    $registry_paths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $empty_line | Out-String
} Else {
    $empty_line | Out-String
    "Running in a 32-bit subsystem" | Out-String
    $64 = $false
    $bit_number = "32"
    $registry_paths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $empty_line | Out-String
}
$firefox_is_installed = $false
If ((Check-InstalledSoftware "*Firefox*") -ne $null) {
    $firefox_is_installed = $true
} Else {
    $continue = $true
}
$32_bit_firefox_is_installed = $false
$64_bit_firefox_is_installed = $false
$registry_paths_selection = Get-ItemProperty $registry_paths -ErrorAction SilentlyContinue | Where-Object { ($_.DisplayName -like "*Firefox*" ) -and ($_.Publisher -like "Mozilla*" )}
If ($registry_paths_selection -ne $null) {

    ForEach ($item in $registry_paths_selection) {

        # Custom Values
        If (($item.DisplayName.Split(" ")[-1] -match "\(") -eq $false) {
            $locale = ($item.DisplayName.Split(" ")[-1]).Replace(")","")
        } Else {
            $continue = $true
        } # Else


        If (($item.DisplayName.Split(" ")[-1] -match "\(x") -eq $true) {

            If ($item.DisplayName.Split(" ")[-1] -like "(x86")  {
                $32_bit_firefox_is_installed = $true
                $type = "32-bit"
            } ElseIf ($item.DisplayName.Split(" ")[-1] -like "(x64")  {
                $64_bit_firefox_is_installed = $true
                $type = "64-bit"
            } Else {
                $continue = $true
            } # Else

        } ElseIf (($item.DisplayName.Split(" ")[-2] -match "\(x") -eq $true) {

            If ($item.DisplayName.Split(" ")[-2] -like "(x86")  {
                $32_bit_firefox_is_installed = $true
                $type = "32-bit"
            } ElseIf ($item.DisplayName.Split(" ")[-2] -like "(x64")  {
                $64_bit_firefox_is_installed = $true
                $type = "64-bit"
            } Else {
                $continue = $true
            } # Else

        } Else {
            $continue = $true
        } # Else

       # $product_version_enum = ((Get-ItemProperty -Path "C:\Program Files (x86)\Mozilla Firefox\Firefox.exe" -ErrorAction SilentlyContinue -Name VersionInfo).VersionInfo).ProductVersion
        $product_version_enum = ((Get-ItemProperty -Path "$($item.InstallLocation)\Firefox.exe" -ErrorAction SilentlyContinue -Name VersionInfo).VersionInfo).ProductVersion
        $test_stability = $product_version_enum -match "(\d+)\.(\d+)\.(\d+)"
        $test_major = $product_version_enum -match "(\d+)\.(\d+)"
        If (($product_version_enum -ne $null) -and ($test_stability -eq $true)) { $product_version_enum -match "(?<C1>\d+)\.(?<C2>\d+)\.(?<C3>\d+)" | Out-Null } Else { $continue = $true }
        If (($product_version_enum -ne $null) -and ($test_stability -eq $false) -and ($test_major -eq $true)) { $product_version_enum -match "(?<C1>\d+)\.(?<C2>\d+)" | Out-Null } Else { $continue = $true }


                            $firefox_enumeration += $obj_firefox = New-Object -TypeName PSCustomObject -Property @{
                                'Name'                          = $item.DisplayName.Replace("(TM)","")
                                'Publisher'                     = $item.Publisher
                                'Product'                       = $item.DisplayName.Split(" ")[1]
                                'Type'                          = $type
                                'Locale'                        = $locale
                                'Major Version'                 = If ($Matches.C1 -ne $null) { $Matches.C1 } Else { $continue = $true }
                                'Minor Version'                 = If ($Matches.C2 -ne $null) { $Matches.C2 } Else { $continue = $true }
                                'Build Number'                  = If ($Matches.C3 -ne $null) { $Matches.C3 } Else { "-" }
                                'Computer'                      = $computer
                                'Install Location'              = $item.InstallLocation
                                'Standard Uninstall String'     = $item.UninstallString.Trim('"')
                                'Release Notes'                 = $item.URLUpdateInfo
                                'Identifying Number'            = $item.PSChildName
                                'Version'                       = $item.DisplayVersion
                            } # New-Object
    } # foreach ($item)


        # Display the Firefox Version Enumeration in console
        If ($firefox_enumeration -ne $null) {
            $firefox_enumeration.PSObject.TypeNames.Insert(0,"Firefox Version Enumeration")
            $firefox_enumeration_selection = $firefox_enumeration | Select-Object 'Name','Publisher','Product','Type','Locale','Major Version','Minor Version','Build Number','Computer','Install Location','Standard Uninstall String','Release Notes','Version'
            $empty_line | Out-String
            $header_firefox_enumeration = "Enumeration of Firefox Versions Found on the System"
            $coline_firefox_enumeration = "---------------------------------------------------"
            Write-Output $header_firefox_enumeration
            $coline_firefox_enumeration | Out-String
            Write-Output $firefox_enumeration_selection
        } Else {
            $continue = $true
        } # Else

} Else {
    $continue = $true
}
$multiple_firefoxes = $false
If ((($firefox_enumeration | Measure-Object Name).Count) -eq 0) {
    Write-Verbose "No Firefox seems to be installed on the system."
} ElseIf ((($firefox_enumeration | Measure-Object Name).Count) -eq 1) {
    $continue = $true
} ElseIf ((($firefox_enumeration | Measure-Object Name).Count) -ge 2) {
    $empty_line | Out-String
    Write-Warning "More than one instance of Firefox seems to be installed on the system."
    $multiple_firefoxes = $true
} Else {
    $continue = $true
}
If (([Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet) -eq $false) {
    $empty_line | Out-String
    Return "The Internet connection doesn't seem to be working. Exiting without checking the latest Firefox version numbers or without updating Firefox (at Step 6)."
} Else {
    Write-Verbose 'Checking the most recent Firefox version numbers from the Mozilla website...'
}
$baseline_url = "https://product-details.mozilla.org/1.0/firefox_versions.json"
$baseline_file = "$path\firefox_current_versions.json"

        try
        {
            $download_baseline = New-Object System.Net.WebClient
            $download_baseline.DownloadFile($baseline_url, $baseline_file)
        }
        catch [System.Net.WebException]
        {
            Write-Warning "Failed to access $baseline_url"
            If (([Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet) -eq $true) {
                $page_exception_text = "Please consider running this script again. Sometimes this Mozilla page just isn't queryable for no apparent reason. The success rate 'in the second go' usually seems to be a bit higher."
                $empty_line | Out-String
                Write-Output $page_exception_text
            } Else {
                $continue = $true
            } # Else
            $empty_line | Out-String
            Return "Exiting without checking the latest Firefox version numbers or without updating Firefox (at Step 7)."
        }
$history_url = "https://product-details.mozilla.org/1.0/firefox_history_stability_releases.json"
$history_file = "$path\firefox_release_history.json"
        try
        {
            $download_history = New-Object System.Net.WebClient
            $download_history.DownloadFile($history_url, $history_file)
        }
        catch [System.Net.WebException]
        {
            Write-Warning "Failed to access $history_url"
            If (([Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet) -eq $true) {
                $empty_line | Out-String
                Write-Output $page_exception_text
            } Else {
                $continue = $true
            } # Else
            $empty_line | Out-String
            Return "Exiting without checking the latest Firefox version numbers or without updating Firefox (at Step 7 while trying to download the history file)."
        }
$major_url = "https://product-details.mozilla.org/1.0/firefox_history_major_releases.json"
$major_file = "$path\firefox_major_versions.json"
        try
        {
            $download_major = New-Object System.Net.WebClient
            $download_major.DownloadFile($major_url, $major_file)
        }
        catch [System.Net.WebException]
        {
            Write-Warning "Failed to access $major_url"
            If (([Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet) -eq $true) {
                $empty_line | Out-String
                Write-Output $page_exception_text
            } Else {
                $continue = $true
            } # Else
            $empty_line | Out-String
            Return "Exiting without checking the latest Firefox version numbers or without updating Firefox (at Step 7 while trying to download a file containing the major version release dates)."
        }
$language_url = "https://product-details.mozilla.org/1.0/languages.json"
$language_file = "$path\firefox_languages.json"
        try
        {
            $download_language = New-Object System.Net.WebClient
            $download_language.DownloadFile($language_url, $language_file)
        }
        catch [System.Net.WebException]
        {
            Write-Warning "Failed to access $language_url"
            If (([Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet) -eq $true) {
                $empty_line | Out-String
                Write-Output $page_exception_text
            } Else {
                $continue = $true
            } # Else
            $empty_line | Out-String
            Return "Exiting without checking the latest Firefox version numbers or without updating Firefox (at Step 7 while trying to download the languages file)."
        }
$region_url = "https://product-details.mozilla.org/1.0/regions/en-US.json"
$region_file = "$path\firefox_regions.json"
        try
        {
            $download_region = New-Object System.Net.WebClient
            $download_region.DownloadFile($region_url, $region_file)
        }
        catch [System.Net.WebException]
        {
            Write-Warning "Failed to access $region_url"
            If (([Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet) -eq $true) {
                $empty_line | Out-String
                Write-Output $page_exception_text
            } Else {
                $continue = $true
            } # Else
            $empty_line | Out-String
            Return "Exiting without checking the latest Firefox version numbers or without updating Firefox (at Step 7 while trying to download the regions file)."
        }
Start-Sleep -Seconds 2
$history_conversion = [System.IO.File]::ReadAllText($history_file).Replace("}",", ")
$major_conversion = [System.IO.File]::ReadAllText($major_file).Replace("{","")
$all_firefox = [string]$history_conversion + $major_conversion
If ((($PSVersionTable.PSVersion).Major -lt 3) -or (($PSVersionTable.PSVersion).Major -eq $null)) {

    # PowerShell v2 or earlier JSON import                                                    # Credit: Goyuix: "Read Json Object in Powershell 2.0"
    # Requires .NET 3.5 or later
    $powershell_v2_or_earlier = $true

            If (($PSVersionTable.PSVersion).Major -eq $null) {
                $powershell_v1 = $true
                # LoadWithPartialName is obsolete, source: https://msdn.microsoft.com/en-us/library/system.reflection.assembly(v=vs.110).aspx
                [System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")
            } ElseIf (($PSVersionTable.PSVersion).Major -lt 3) {
                $powershell_v2 = $true
                Add-Type -AssemblyName "System.Web.Extensions"
            } Else {
                $continue = $true
            } # Else

    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $latest = $serializer.DeserializeObject((Get-Content -Path $baseline_file) -join "`n")
    $history = $serializer.DeserializeObject((Get-Content -Path $history_file) -join "`n")
    $major = $serializer.DeserializeObject((Get-Content -Path $major_file) -join "`n")
    $all_dates = $serializer.DeserializeObject(($all_firefox) -join "`n")    
    $language = $serializer.DeserializeObject((Get-Content -Path $language_file) -join "`n")
    $region = $serializer.DeserializeObject((Get-Content -Path $region_file) -join "`n")    
    try
    {
        $latest_release_date = (Get-Date ($all_dates.Get_Item("$($latest.LATEST_FIREFOX_VERSION)"))).ToShortDateString()
    }
    catch
    {
        $message = $error[0].Exception
        Write-Verbose $message
    }
} ElseIf (($PSVersionTable.PSVersion).Major -ge 3) {
    $latest = (Get-Content -Raw -Path $baseline_file) | ConvertFrom-Json
    $history = (Get-Content -Raw -Path $history_file) | ConvertFrom-Json
    $major = (Get-Content -Raw -Path $major_file) | ConvertFrom-Json
    $all_dates = ($all_firefox) | ConvertFrom-Json      
    $language = (Get-Content -Raw -Path $language_file) | ConvertFrom-Json
    $region = (Get-Content -Raw -Path $region_file) | ConvertFrom-Json
    try
    {
        $latest_release_date = (Get-Date ($all_dates | Select-Object -ExpandProperty "$($latest.LATEST_FIREFOX_VERSION)")).ToShortDateString()
    }
    catch
    {
        $message = $error[0].Exception
        Write-Verbose $message
    }
} Else {
    $continue = $true
}
    If ($latest_release_date -eq $null) {
        $raw_conversion = $all_firefox.Replace("{","").Replace(": "," = ").Replace(",","`r`n").Replace("}","`r`n").Replace('"','')
        $release_dates = ConvertFrom-StringData -StringData $raw_conversion
        $release_dates_list = $release_dates.GetEnumerator() | Sort-Object Value -Descending

            If ($release_dates.ContainsKey("$($latest.LATEST_FIREFOX_VERSION)")) {
                $latest_release_date = $release_dates.Get_Item("$($latest.LATEST_FIREFOX_VERSION)")
            } Else {
                $latest_release_date = "[unknown]"
            } # Else

    } Else {
        $continue = $true
    }
                    $latest_firefox += $obj_latest = New-Object -TypeName PSCustomObject -Property @{
                        'Nightly'                               = $latest.FIREFOX_NIGHTLY
                        'Aurora'                                = $latest.FIREFOX_AURORA
                        'In Development'                        = $latest.LATEST_FIREFOX_DEVEL_VERSION
                        'Released Beta'                         = $latest.LATEST_FIREFOX_RELEASED_DEVEL_VERSION
                        'Extended-Support Release (ESR)'        = $latest.FIREFOX_ESR
                        'Extended-Support Release (ESR) Next'   = $latest.FIREFOX_ESR_NEXT
                        'Old'                                   = $latest.LATEST_FIREFOX_OLDER_VERSION
                        'Latest Release Date'                   = $latest_release_date
                        'Major Versions'                        = $major_url
                        'Release History'                       = $history_url
                        'History'                               = "https://www.mozilla.org/en-US/firefox/releases/"
                        'Info'                                  = [string]"https://www.mozilla.org/en-US/firefox/" + $latest.LATEST_FIREFOX_VERSION + "/releasenotes/"
                        'Current'                               = $latest.LATEST_FIREFOX_VERSION
                    } # New-Object
                $latest_firefox.PSObject.TypeNames.Insert(0,"Latest Firefox Versions")
                $most_recent_firefox_version = $latest_firefox | Select-Object -ExpandProperty Current
        If ($latest_firefox -ne $null) {
            $latest_firefox_selection = $latest_firefox | Select-Object 'Nightly','Aurora','In Development','Released Beta','Extended-Support Release (ESR)','Old','Latest Release Date','Release History','History','Info','Current'
            $empty_line | Out-String
            $header_firefox_enumeration = "Latest Firefox Versions"
            $coline_firefox_enumeration = "-----------------------"
            Write-Output $header_firefox_enumeration
            $coline_firefox_enumeration | Out-String
            Write-Output $latest_firefox_selection
        } Else {
            $continue = $true
        }
$downloading_firefox_is_required = $false
$downloading_firefox_32_is_required = $false
$downloading_firefox_64_is_required = $false
If ($firefox_is_installed -eq $true) {

    $most_recent_firefox_already_exists = Check-InstalledSoftware "Mozilla Firefox $($most_recent_firefox_version)*"
    $most_recent_32_bit_firefox_already_exists = Check-InstalledSoftware "Mozilla Firefox $($most_recent_firefox_version) (x86*"
    $most_recent_64_bit_firefox_already_exists = Check-InstalledSoftware "Mozilla Firefox $($most_recent_firefox_version) (x64*"
    $all_32_bit_firefoxes = $firefox_enumeration | Where-Object { $_.Type -eq "32-bit" }
    $number_of_32_bit_firefoxes = ($all_32_bit_firefoxes | Measure-Object).Count
    $all_64_bit_firefoxes = $firefox_enumeration | Where-Object { $_.Type -eq "64-bit" }
    $number_of_64_bit_firefoxes = ($all_64_bit_firefoxes | Measure-Object).Count


    # 32-bit
    If ($32_bit_firefox_is_installed -eq $false) {
        $continue = $true

    } ElseIf (($32_bit_firefox_is_installed -eq $true) -and ($most_recent_32_bit_firefox_already_exists) -and ($number_of_32_bit_firefoxes -eq 1)) {

        # $downloading_firefox_32_is_required = $false
        $locale = If (($most_recent_32_bit_firefox_already_exists.DisplayName.Split(" ")[-1] -match "\(") -eq $false) {
                        If ($powershell_v2_or_earlier -eq $true) {
                            $language.Get_Item(($most_recent_32_bit_firefox_already_exists.DisplayName.Split(" ")[-1]).Replace(")",""))
                        } Else {
                            $language | Select-Object -ExpandProperty (($most_recent_32_bit_firefox_already_exists.DisplayName.Split(" ")[-1]).Replace(")",""))
                        } # Else

                    } Else {
                        $continue = $true
                    } # Else ($locale)

        If ($powershell_v2_or_earlier -eq $true) {
            try
            {
                $release_date = $all_dates.Get_Item($most_recent_32_bit_firefox_already_exists.DisplayVersion)
            }
            catch
            {
                $message = $error[0].Exception
                Write-Verbose $message
            }
        } Else {
            try
            {
                $release_date = $all_dates | Select-Object -ExpandProperty $most_recent_32_bit_firefox_already_exists.DisplayVersion
            }
            catch
            {
                $message = $error[0].Exception
                Write-Verbose $message
            }
        } # Else

                            $currently_installed_32 += New-Object -TypeName PSCustomObject -Property @{
                                'Name'                          = $most_recent_32_bit_firefox_already_exists.DisplayName.replace("(TM)","")
                                'Publisher'                     = $most_recent_32_bit_firefox_already_exists.Publisher
                                'Product'                       = $most_recent_32_bit_firefox_already_exists.DisplayName.Split(" ")[1]
                                'Type'                          = "32-bit"
                                'Locale'                        = $locale
                                'Computer'                      = $computer
                                'Install Location'              = $most_recent_32_bit_firefox_already_exists.InstallLocation
                                'Release Notes'                 = $most_recent_32_bit_firefox_already_exists.URLUpdateInfo
                                'Standard Uninstall String'     = $most_recent_32_bit_firefox_already_exists.UninstallString.Trim('"')
                                'Identifying Number'            = $most_recent_32_bit_firefox_already_exists.PSChildName
                                'Release_Date'                  = $release_date
                                'Version'                       = $most_recent_32_bit_firefox_already_exists.DisplayVersion

                            } # New-Object
                        $currently_installed_32.PSObject.TypeNames.Insert(0,"Existing Current Firefox 32-bit")

        $empty_line | Out-String
        Write-Output "Currently (until the next Firefox version is released) the $($($currently_installed_32.Locale).English) 32-bit $($currently_installed_32.Name) released on $((Get-Date ($currently_installed_32.Release_Date)).ToShortDateString()) doesn't need any further maintenance or care."

    } Else {
        $downloading_firefox_32_is_required = $true
        $downloading_firefox_is_required = $true

        ForEach ($32_bit_firefox in $all_32_bit_firefoxes) {

            If ($32_bit_firefox.Version -eq $most_recent_firefox_version) {

                        If ($powershell_v2_or_earlier -eq $true) {
                            try
                            {
                                $release_date = $all_dates.Get_Item($32_bit_firefox.Version)
                            }
                            catch
                            {
                                $message = $error[0].Exception
                                Write-Verbose $message
                            }
                        } Else {
                            try
                            {
                                $release_date_32 = $all_dates | Select-Object -ExpandProperty "$($32_bit_firefox.Version)"
                            }
                            catch
                            {
                                $message = $error[0].Exception
                                Write-Verbose $message
                            }
                        } # Else

                $empty_line | Out-String
                Write-Output "Currently (until the next Firefox version is released) the 32-bit $($32_bit_firefox.Name) released on $((Get-Date ($release_date_32)).ToShortDateString()) doesn't need any further maintenance or care."
            } Else {
                $empty_line | Out-String
                Write-Warning "$($32_bit_firefox.Name) seems to be outdated."
                $empty_line | Out-String
                Write-Output "The most recent non-beta Firefox version is $most_recent_firefox_version. The installed 32-bit Firefox version $($32_bit_firefox.Version) needs to be updated."
            } # Else


        } # ForEach
    } # Else


    # 64-bit
    If ($64_bit_firefox_is_installed -eq $false) {
        $continue = $true

    } ElseIf (($64_bit_firefox_is_installed -eq $true) -and ($most_recent_64_bit_firefox_already_exists) -and ($number_of_64_bit_firefoxes -eq 1)) {

        # $downloading_firefox_64_is_required = $false
        $locale = If (($most_recent_64_bit_firefox_already_exists.DisplayName.Split(" ")[-1] -match "\(") -eq $false) {
                        If ($powershell_v2_or_earlier -eq $true) {
                            $language.Get_Item(($most_recent_64_bit_firefox_already_exists.DisplayName.Split(" ")[-1]).Replace(")",""))
                        } Else {
                            $language | Select-Object -ExpandProperty (($most_recent_64_bit_firefox_already_exists.DisplayName.Split(" ")[-1]).Replace(")",""))
                        } # Else

                    } Else {
                        $continue = $true
                    } # Else ($locale)

        If ($powershell_v2_or_earlier -eq $true) {
            try
            {
                $release_date = $all_dates.Get_Item($most_recent_64_bit_firefox_already_exists.DisplayVersion)
            }
            catch
            {
                $message = $error[0].Exception
                Write-Verbose $message
            }
        } Else {
            try
            {
                $release_date = $all_dates | Select-Object -ExpandProperty $most_recent_64_bit_firefox_already_exists.DisplayVersion
            }
            catch
            {
                $message = $error[0].Exception
                Write-Verbose $message
            }
        } # Else

                            $currently_installed_64 += New-Object -TypeName PSCustomObject -Property @{
                                'Name'                          = $most_recent_64_bit_firefox_already_exists.DisplayName.replace("(TM)","")
                                'Publisher'                     = $most_recent_64_bit_firefox_already_exists.Publisher
                                'Product'                       = $most_recent_64_bit_firefox_already_exists.DisplayName.Split(" ")[1]
                                'Type'                          = "64-bit"
                                'Locale'                        = $locale
                                'Computer'                      = $computer
                                'Install Location'              = $most_recent_64_bit_firefox_already_exists.InstallLocation
                                'Release Notes'                 = $most_recent_64_bit_firefox_already_exists.URLUpdateInfo
                                'Standard Uninstall String'     = $most_recent_64_bit_firefox_already_exists.UninstallString.Trim('"')
                                'Identifying Number'            = $most_recent_64_bit_firefox_already_exists.PSChildName
                                'Release_Date'                  = $release_date
                                'Version'                       = $most_recent_64_bit_firefox_already_exists.DisplayVersion

                            } # New-Object
                        $currently_installed_64.PSObject.TypeNames.Insert(0,"Existing Current Firefox 64-bit")

        $empty_line | Out-String
        Write-Output "Currently (until the next Firefox version is released) the $($($currently_installed_64.Locale).English) 64-bit $($currently_installed_64.Name) released on $((Get-Date ($currently_installed_64.Release_Date)).ToShortDateString()) doesn't need any further maintenance or care."

    } Else {
        $downloading_firefox_64_is_required = $true
        $downloading_firefox_is_required = $true

        ForEach ($64_bit_firefox in $all_64_bit_firefoxes) {

            If ($64_bit_firefox.Version -eq $most_recent_firefox_version) {

                        If ($powershell_v2_or_earlier -eq $true) {
                            try
                            {
                                $release_date_64 = $all_dates.Get_Item($64_bit_firefox.Version)
                            }
                            catch
                            {
                                $message = $error[0].Exception
                                Write-Verbose $message
                            }
                        } Else {
                            try
                            {
                                $release_date_64 = $all_dates | Select-Object -ExpandProperty "$($64_bit_firefox.Version)"
                            }
                            catch
                            {
                                $message = $error[0].Exception
                                Write-Verbose $message
                            }
                        } # Else

                $empty_line | Out-String
                Write-Output "Currently (until the next Firefox version is released) the 64-bit $($64_bit_firefox.Name) released on $((Get-Date ($release_date_64)).ToShortDateString()) doesn't need any further maintenance or care."
            } Else {
                $empty_line | Out-String
                Write-Warning "$($64_bit_firefox.Name) seems to be outdated."
                $empty_line | Out-String
                Write-Output "The most recent non-beta Firefox version is $most_recent_firefox_version. The installed 64-bit Firefox version $($64_bit_firefox.Version) needs to be updated."
            } # Else

        } # ForEach
    } # Else

} Else {
    $continue = $true
}
If ($firefox_is_installed -eq $true) {

    $32_bit_uninstall_string = $all_32_bit_firefoxes | Select-Object -ExpandProperty 'Standard Uninstall String'
    $64_bit_uninstall_string = $all_64_bit_firefoxes | Select-Object -ExpandProperty 'Standard Uninstall String'

                $obj_maintenance += New-Object -TypeName PSCustomObject -Property @{
                    'Open the Firefox primary profile location'     = [string]'Invoke-Item ' + $quote + [Environment]::GetFolderPath("ApplicationData") + '\Mozilla\Firefox\Profiles' + $unquote
                    'Open the Firefox secondary profile location'   = [string]'Invoke-Item ' + $quote + [Environment]::GetFolderPath("LocalApplicationData") + '\Mozilla\Firefox\Profiles' + $unquote
                    'Open the updates.xml file location'            = [string]'Invoke-Item ' + $quote + [Environment]::GetFolderPath("LocalApplicationData") + '\Mozilla\updates\' + $unquote
                    'Uninstall the 32-bit Firefox'                  = If ($32_bit_firefox_is_installed -eq $true) { $32_bit_uninstall_string } Else { [string]'[not installed]' }
                    'Uninstall the 64-bit Firefox'                  = If ($64_bit_firefox_is_installed -eq $true) { $64_bit_uninstall_string } Else { [string]'[not installed]' }

                } # New-Object
            $obj_maintenance.PSObject.TypeNames.Insert(0,"Maintenance")
            $obj_maintenance_selection = $obj_maintenance | Select-Object 'Open the Firefox primary profile location','Open the Firefox secondary profile location','Open the updates.xml file location','Uninstall the 32-bit Firefox','Uninstall the 64-bit Firefox'


        # Display the Maintenance table in console
        $empty_line | Out-String
        $header_maintenance = "Maintenance"
        $coline_maintenance = "-----------"
        Write-Output $header_maintenance
        $coline_maintenance | Out-String
        Write-Output $obj_maintenance_selection




        $obj_downloading += New-Object -TypeName PSCustomObject -Property @{
            '32-bit Firefox'   = If ($32_bit_firefox_is_installed -eq $true) { $downloading_firefox_32_is_required } Else { [string]'-' }
            '64-bit Firefox'   = If ($64_bit_firefox_is_installed -eq $true) { $downloading_firefox_64_is_required } Else { [string]'-' }
        } # New-Object
    $obj_downloading.PSObject.TypeNames.Insert(0,"Maintenance Is Required for These Firefox Versions")
    $obj_downloading_selection = $obj_downloading | Select-Object '32-bit Firefox','64-bit Firefox'


    # Display in console which installers for Firefox need to be downloaded
    $empty_line | Out-String
    $header_downloading = "Maintenance Is Required for These Firefox Versions"
    $coline_downloading = "--------------------------------------------------"
    Write-Output $header_downloading
    $coline_downloading | Out-String
    Write-Output $obj_downloading_selection
    $empty_line | Out-String

} Else {
    $continue = $true
}
If ($firefox_is_installed -eq $true) {

    If (($downloading_firefox_is_required -eq $false) -and ($downloading_firefox_32_is_required -eq $false) -and ($downloading_firefox_64_is_required -eq $false)) {
        Return "The installed Firefox seems to be OK."
    } Else {
        $continue = $true
    } # Else
} Else {
    Write-Warning "No Firefox seems to be installed on the system."
    $empty_line | Out-String
    $no_firefox_text_1 = "This script didn't detect that any version of Firefox would have been installed."
    $no_firefox_text_2 = "Please consider installing Firefox by visiting"
    $no_firefox_text_3 = "https://www.mozilla.org/en-US/firefox/all/"
    $no_firefox_text_4 = "For URLs of the full installation files please, for example, see the page"
    $no_firefox_text_5 = "https://ftp.mozilla.org/pub/firefox/releases/latest/README.txt"
    $no_firefox_text_6 = "and for uninstalling Firefox, please visit"
    $no_firefox_text_7 = "https://support.mozilla.org/en-US/kb/uninstall-firefox-from-your-computer"
    Write-Output $no_firefox_text_1
    Write-Output $no_firefox_text_2
    Write-Output $no_firefox_text_3
    Write-Output $no_firefox_text_4
    Write-Output $no_firefox_text_5
    Write-Output $no_firefox_text_6
    Write-Output $no_firefox_text_7
    If (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator") -eq $true) {
        $empty_line | Out-String
        Write-Verbose "Welcome to the Admin Corner." -verbose
        $title_1 = "Install Firefox - The Fundamentals (Step 1/3)"
        $message_1 = "Would you like to install one of the Firefox versions (32-bit or 64-bit in a certain language) with this script?"

        $yes = New-Object System.Management.Automation.Host.ChoiceDescription    "&Yes",    "Yes:     tries to download and install one of the Firefox versions specified on the next two steps."
        $no = New-Object System.Management.Automation.Host.ChoiceDescription     "&No",     "No:      exits from this script (similar to Ctrl + C)."
        $exit = New-Object System.Management.Automation.Host.ChoiceDescription   "&Exit",   "Exit:    exits from this script (similar to Ctrl + C)."
        $abort = New-Object System.Management.Automation.Host.ChoiceDescription  "&Abort",  "Abort:   exits from this script (similar to Ctrl + C)."
        $cancel = New-Object System.Management.Automation.Host.ChoiceDescription "&Cancel", "Cancel:  exits from this script (similar to Ctrl + C)."

        $options_1 = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no, $exit, $abort, $cancel)
        $result_1 = $host.ui.PromptForChoice($title_1, $message_1, $options_1, 1)

            switch ($result_1)
                {
                    0 {
                    "Yes. Proceeding to the next step.";
                    $admin_corner = $true
                    $continue = $true
                    }
                    1 {
                    "No. Exiting from Install Firefox script.";
                    Exit
                    }
                    2 {
                    "Exit. Exiting from Install Firefox script.";
                    Exit
                    }
                    3 {
                    "Abort. Exiting from Install Firefox script.";
                    Exit
                    }
                    4 {
                    "Cancel. Exiting from Install Firefox script.";
                    Exit
                    } # 4
                } # switch

        $empty_line | Out-String
        $title_2 = "Install Firefox - The Bit Version (Step 2/3)"
        $message_2 = "Which bit version (32-bit or 64-bit) of Firefox would you like to install?"

        $32_bit = New-Object System.Management.Automation.Host.ChoiceDescription "&32-bit", "32-bit:    tries to download and install the 32-bit version of Firefox."
        $64_bit = New-Object System.Management.Automation.Host.ChoiceDescription "&64-bit", "64-bit:    tries to download and install the 64-bit version of Firefox."

        $options_2 = [System.Management.Automation.Host.ChoiceDescription[]]($32_bit, $64_bit, $exit, $abort, $cancel)
        $result_2 = $host.ui.PromptForChoice($title_2, $message_2, $options_2, 4)

            switch ($result_2)
                {
                    0 {
                    "32-bit selected.";
                    $firefox_is_installed = $true
                    $32_bit_firefox_is_installed = $true
                    $original_firefox_version = "[Nonexistent]"
                    $downloading_firefox_is_required = $true
                    $downloading_firefox_32_is_required = $true
                    $os = '&os=win'
                    $bit_number = "32"
                    $continue = $true
                    }
                    1 {
                    "64-bit selected.";
                    $firefox_is_installed = $true
                    $64_bit_firefox_is_installed = $true
                    $original_firefox_version = "[Nonexistent]"
                    $downloading_firefox_is_required = $true
                    $downloading_firefox_64_is_required = $true
                    $os = '&os=win64'
                    $bit_number = "64"
                    $continue = $true
                    }
                    2 {
                    "Exit. Exiting from Install Firefox script.";
                    Exit
                    }
                    3 {
                    "Abort. Exiting from Install Firefox script.";
                    Exit
                    }
                    4 {
                    "Cancel. Exiting from Install Firefox script.";
                    Exit
                    } # 4
                } # switch

        $empty_line | Out-String
        $title_3 = "Install Firefox - The Language (Step 3/3)"
        $message_3 = "Which language version of Firefox would you like to install?"

        $0 = New-Object System.Management.Automation.Host.ChoiceDescription "&0 English (US)", "English (US):  tries to download and install the English (US) version of Firefox."
        $1 = New-Object System.Management.Automation.Host.ChoiceDescription "&1 English (British)", "English (British):  tries to download and install the English (British) version of Firefox."
        $2 = New-Object System.Management.Automation.Host.ChoiceDescription "&2 Arabic",      "Arabic:      tries to download and install the Arabic version of Firefox."
        $3 = New-Object System.Management.Automation.Host.ChoiceDescription "&3 Chinese (Simplified)", "Chinese (Simplified):  tries to download and install the Chinese (Simplified) version of Firefox."
        $4 = New-Object System.Management.Automation.Host.ChoiceDescription "&4 Chinese (Traditional)", "Chinese (Traditional):  tries to download and install the Chinese (Traditional) version of Firefox."
        $5 = New-Object System.Management.Automation.Host.ChoiceDescription "&5 Dutch",       "Dutch:       tries to download and install the Dutch version of Firefox."
        $6 = New-Object System.Management.Automation.Host.ChoiceDescription "&6 French",      "French:      tries to download and install the French version of Firefox."
        $7 = New-Object System.Management.Automation.Host.ChoiceDescription "&7 German",      "German:      tries to download and install the German version of Firefox."
        $8 = New-Object System.Management.Automation.Host.ChoiceDescription "&8 Portuguese (Portugal)", "Portuguese (Portugal):  tries to download and install the Portuguese (Portugal) version of Firefox."
        $9 = New-Object System.Management.Automation.Host.ChoiceDescription "&9 Spanish (Spain)", "Spanish (Spain):  tries to download and install the Spanish (Spain) version of Firefox."
        $b = New-Object System.Management.Automation.Host.ChoiceDescription "&b Bengali (India)", "Bengali (India):  tries to download and install the Bengali (India) version of Firefox."
        $d = New-Object System.Management.Automation.Host.ChoiceDescription "&d Danish",      "Danish:      tries to download and install the Danish version of Firefox."
        $f = New-Object System.Management.Automation.Host.ChoiceDescription "&f Finnish",     "Finnish:     tries to download and install the Finnish version of Firefox."
        $g = New-Object System.Management.Automation.Host.ChoiceDescription "&g Greek",       "Greek:       tries to download and install the Greek version of Firefox."
        $h = New-Object System.Management.Automation.Host.ChoiceDescription "&h Hebrew",      "Hebrew:      tries to download and install the Hebrew version of Firefox."
        $i = New-Object System.Management.Automation.Host.ChoiceDescription "&i Italian",     "Italian:     tries to download and install the Italian version of Firefox."
        $j = New-Object System.Management.Automation.Host.ChoiceDescription "&j Indonesian",  "Indonesian:  tries to download and install the Indonesian version of Firefox."
        $k = New-Object System.Management.Automation.Host.ChoiceDescription "&k Korean",      "Korean:      tries to download and install the Korean version of Firefox."
        $l = New-Object System.Management.Automation.Host.ChoiceDescription "&l Latvian",     "Latvian:     tries to download and install the Latvian version of Firefox."
        $m = New-Object System.Management.Automation.Host.ChoiceDescription "&m Malay",       "Malay:       tries to download and install the Malay version of Firefox."
        $n = New-Object System.Management.Automation.Host.ChoiceDescription "&n Norwegian (Nynorsk)", "Norwegian (Nynorsk):  tries to download and install the Norwegian (Nynorsk) version of Firefox."
        $o = New-Object System.Management.Automation.Host.ChoiceDescription "&o Norwegian (Bokmal)", "Norwegian (Bokmal):  tries to download and install the Norwegian (Bokmal) version of Firefox."
        $p = New-Object System.Management.Automation.Host.ChoiceDescription "&p Punjabi (India)", "Punjabi (India):  tries to download and install the Punjabi (India) version of Firefox."
        $q = New-Object System.Management.Automation.Host.ChoiceDescription "&q Hindi (India)", "Hindi (India):  tries to download and install the Hindi (India) version of Firefox."
        $r = New-Object System.Management.Automation.Host.ChoiceDescription "&r Romanian",    "Romanian:    tries to download and install the Romanian version of Firefox."
        $s = New-Object System.Management.Automation.Host.ChoiceDescription "&s Swedish",     "Swedish:     tries to download and install the Swedish version of Firefox."
        $t = New-Object System.Management.Automation.Host.ChoiceDescription "&t Thai",        "Thai:        tries to download and install the Thai version of Firefox."
        $u = New-Object System.Management.Automation.Host.ChoiceDescription "&u Ukrainian",   "Ukrainian:   tries to download and install the Ukrainian version of Firefox."
        $v = New-Object System.Management.Automation.Host.ChoiceDescription "&v Vietnamese",  "Vietnamese:  tries to download and install the Vietnamese version of Firefox."
        $w = New-Object System.Management.Automation.Host.ChoiceDescription "&w Welsh",       "Welsh:       tries to download and install the Welsh version of Firefox."
        $x = New-Object System.Management.Automation.Host.ChoiceDescription "&x Xhosa",       "Xhosa:       tries to download and install the Xhosa version of Firefox."
        $y = New-Object System.Management.Automation.Host.ChoiceDescription "&y Gaelic (Scotland)", "Gaelic (Scotland):  tries to download and install the Gaelic (Scotland) version of Firefox."
        $z = New-Object System.Management.Automation.Host.ChoiceDescription "&z Uzbek",       "Uzbek:       tries to download and install the Uzbek version of Firefox."

        $options_3 = [System.Management.Automation.Host.ChoiceDescription[]]($0, $1, $2, $3, $4, $5, $6, $7, $8, $9, $b, $d, $f, $g, $h, $i, $j, $k, $l, $m, $n, $o, $p, $q, $r, $s, $t, $u, $v, $w, $x, $y, $z, $exit, $abort, $cancel)
        $result_3 = $host.ui.PromptForChoice($title_3, $message_3, $options_3, 35)

            switch ($result_3)
                {
                    0 {
                    "English (US) selected.";
                    $lang = '&lang=en-US'
                    $continue = $true
                    }
                    1 {
                    "English (British) selected.";
                    $lang = '&lang=en-GB'
                    $continue = $true
                    }
                    2 {
                    "Arabic selected.";
                    $lang = '&lang=ar'
                    $continue = $true
                    }
                    3 {
                    "Chinese (Simplified) selected.";
                    $lang = '&lang=zh-CN'
                    $continue = $true
                    }
                    4 {
                    "Chinese (Traditional) selected.";
                    $lang = '&lang=zh-TW'
                    $continue = $true
                    }
                    5 {
                    "Dutch selected.";
                    $lang = '&lang=nl'
                    $continue = $true
                    }
                    6 {
                    "French selected.";
                    $lang = '&lang=fr'
                    $continue = $true
                    }
                    7 {
                    "German selected.";
                    $lang = '&lang=de'
                    $continue = $true
                    }
                    8 {
                    "Portuguese (Portugal) selected.";
                    $lang = '&lang=pt-PT'
                    $continue = $true
                    }
                    9 {
                    "Spanish (Spain) selected.";
                    $lang = '&lang=es-ES'
                    $continue = $true
                    }
                    10 {
                    "Bengali (India) selected.";
                    $lang = '&lang=bn-IN'
                    $continue = $true
                    }
                    11 {
                    "Danish selected.";
                    $lang = '&lang=da'
                    $continue = $true
                    }
                    12 {
                    "Finnish selected.";
                    $lang = 'lang=fi'
                    $continue = $true
                    }
                    13 {
                    "Greek selected.";
                    $lang = '&lang=el'
                    $continue = $true
                    }
                    14 {
                    "Hebrew selected.";
                    $lang = '&lang=he'
                    $continue = $true
                    }
                    15 {
                    "Italian selected.";
                    $lang = '&lang=it'
                    $continue = $true
                    }
                    16 {
                    "Indonesian selected.";
                    $lang = '&lang=id'
                    $continue = $true
                    }
                    17 {
                    "Korean selected.";
                    $lang = '&lang=ko'
                    $continue = $true
                    }
                    18 {
                    "Latvian selected.";
                    $lang = '&lang=lv'
                    $continue = $true
                    }
                    19 {
                    "Malay selected.";
                    $lang = '&lang=ms'
                    $continue = $true
                    }
                    20 {
                    "Norwegian (Nynorsk) selected.";
                    $lang = '&lang=nn-NO'
                    $continue = $true
                    }
                    21 {
                    "Norwegian (Bokmal) selected.";
                    $lang = '&lang=nb-NO'
                    $continue = $true
                    }
                    22 {
                    "Punjabi (India) selected.";
                    $lang = '&lang=pa-IN'
                    $continue = $true
                    }
                    23 {
                    "Hindi (India) selected.";
                    $lang = '&lang=hi-IN'
                    $continue = $true
                    }
                    24 {
                    "Romanian selected.";
                    $lang = '&lang=ro'
                    $continue = $true
                    }
                    25 {
                    "Swedish selected.";
                    $lang = '&lang=sv-SE'
                    $continue = $true
                    }
                    26 {
                    "Thai selected.";
                    $lang = '&lang=th'
                    $continue = $true
                    }
                    27 {
                    "Ukrainian selected.";
                    $lang = '&lang=uk'
                    $continue = $true
                    }
                    28 {
                    "Vietnamese selected.";
                    $lang = '&lang=vi'
                    $continue = $true
                    }
                    29 {
                    "Welsh selected.";
                    $lang = '&lang=cy'
                    $continue = $true
                    }
                    30 {
                    "Xhosa selected.";
                    $lang = '&lang=xh'
                    $continue = $true
                    }
                    31 {
                    "Gaelic (Scotland) selected.";
                    $lang = '&lang=gd'
                    $continue = $true
                    }
                    32 {
                    "Uzbek selected.";
                    $lang = '&lang=uz'
                    $continue = $true
                    }
                    33 {
                    "Exit. Exiting from Install Firefox script.";
                    Exit
                    }
                    34 {
                    "Abort. Exiting from Install Firefox script.";
                    Exit
                    }
                    35 {
                    "Cancel. Exiting from Install Firefox script.";
                    Exit
                    } # 35
                } # switch

        # Determine the Download URL based on the selections made by the user.
        # Source: https://ftp.mozilla.org/pub/firefox/releases/latest/README.txt
        # https://download.mozilla.org/?product=firefox-latest&os=win&lang=en-US
        $download_url = [string]'https://download.mozilla.org/?product=firefox-latest' + $os + $lang

    } Else {
        Exit
    }
}
If (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator") -eq $false) {
    Write-Warning "It seems that this script is run in a 'normal' PowerShell window."
    $empty_line | Out-String
    Write-Verbose "Please consider running this script in an elevated (administrator-level) PowerShell window." -verbose
    $empty_line | Out-String
    $admin_text = "For performing system altering procedures, such as installing Firefox the elevated rights are mandatory. An elevated PowerShell session can, for example, be initiated by starting PowerShell with the 'run as an administrator' option."
    Write-Output $admin_text
    $empty_line | Out-String
    # Write-Verbose "Even though it could also be possible to write a self elevating PowerShell script (https://blogs.msdn.microsoft.com/virtual_pc_guy/2010/09/23/a-self-elevating-powershell-script/) or run commands elevated in PowerShell (http://powershell.com/cs/blogs/tips/archive/2014/03/19/running-commands-elevated-in-powershell.aspx) with the UAC prompts, the new UAC pop-up window may come as a surprise to the end-user, who isn't neccesarily aware that this script needs the elevated rights to complete the intended actions."
    Return "Exiting without updating (at Step 12)."
} Else {
    $continue = $true
}
$empty_line | Out-String
$timestamp = Get-Date -Format HH:mm:ss
$update_text = "$timestamp - Initiating the Firefox Update Protocol..."
Write-Output $update_text                                                           
$script_path = Split-Path -parent $MyInvocation.MyCommand.Definition
$activity             = "Updating Firefox"
$status               = "Status"
$id                   = 1 # For using more than one progress bar
$total_steps          = 19 # Total number of the steps or tasks, which will increment the progress bar
$task_number          = 0.2 # An increasing numerical value, which is set at the beginning of each of the steps that increments the progress bar (and the value should be less or equal to total_steps). In essence, this is the "progress" of the progress bar.
$task                 = "Setting Initial Variables" # A description of the current operation, which is set at the beginning of each of the steps that increments the progress bar.
Write-Progress -Id $id -Activity $activity -Status $status -CurrentOperation $task -PercentComplete (($task_number / $total_steps) * 100)
                                              # Credit: Jeff: "Powershell show elapsed time"
    If ($Host.UI.RawUI.KeyAvailable -and ("q" -eq $Host.UI.RawUI.ReadKey("IncludeKeyUp,NoEcho").Character)) {
        Write-Host " ...Stopping the Firefox Update Protocol...";
        Break;
    } ElseIf ($Host.UI.RawUI.KeyAvailable -and (([char]27) -eq $Host.UI.RawUI.ReadKey("IncludeKeyUp,NoEcho").Character)) {
        Write-Host " ...Stopping the Firefox Update Protocol..."; Break;
    } Else {
        $continue = $true
    } # Else
$task_number = 1
$task = "Writing the Firefox installation configuration ini file..."
Write-Progress -Id $id -Activity $activity -Status $status -CurrentOperation $task -PercentComplete (($task_number / $total_steps) * 100)

$ini_file = "firefox_configuration.ini"
$ini = New-Item -ItemType File -Path "$path\$ini_file" -Force
$ini
Add-Content $ini -Value ("[Install]
;
; Remove the semicolon (;) to un-comment a line.
;
; The name of the directory where the application will be installed in the
; system's program files directory. The security context the installer is
; running in must have write access to the installation directory. Also, the
; directory must not exist or if it exists it must be a directory and not a
; file. If any of these conditions are not met the installer will abort the
; installation with an error level of 2. If this value is specified
; then InstallDirectoryPath will be ignored.
; InstallDirectoryName=Mozilla Firefox

; The full path to the directory to install the application. The security
; context the installer is running in must have write access to the
; installation directory. Also, the directory must not exist or if it exists
; it must be a directory and not a file. If any of these conditions are not met
; the installer will abort the installation with an error level of 2.
; InstallDirectoryPath=c:\firefox\

; By default all of the following shortcuts are created. To prevent the
; creation of a shortcut specify false for the shortcut you don't want created.

; Create a shortcut for the application in the current user's QuickLaunch
; directory.
; QuickLaunchShortcut=false

; Create a shortcut for the application on the desktop. This will create the
; shortcut in the All Users Desktop directory and if that fails this will
; attempt to create the shortcuts in the current user's Start Menu directory.
; DesktopShortcut=false

; Create shortcuts for the application in the Start Menu. This will create the
; shortcuts in the All Users Start Menu directory and if that fails this will
; attempt to create the shortcuts in the current user's Start Menu directory.
; StartMenuShortcuts=false

; The directory name to use for the StartMenu folder (not available with
; Firefox 4.0 and above - see the note below).
; Note: if StartMenuShortcuts=false is specified then this will be ignored.
; StartMenuDirectoryName=Mozilla Firefox

; The MozillaMaintenance service is used for silent updates and may be used
; for other maintenance related tasks. It is an optional component. This
; option can be used in Firefox 16 or later to skip installing the service.
MaintenanceService=false")
$task_number = 2
$task = "Determining the required language version and the correct download URL..."
Write-Progress -Id $id -Activity $activity -Status $status -CurrentOperation $task -PercentComplete (($task_number / $total_steps) * 100)
If (($multiple_firefoxes -ne $true) -and ($admin_corner -ne $true)) {


            If ($downloading_firefox_32_is_required -eq $true) {
                $os = '&os=win'
                $bit_number = "32"
            } ElseIf ($downloading_firefox_64_is_required -eq $true) {
                $os = '&os=win64'
                $bit_number = "64"
            } Else {
                $continue = $true
            } # Else


            # $system_language_and_region = (Get-Culture).Name
            # $system_language_abbreviation = (Get-Culture).TwoLetterISOLanguageName
            # $system_language = (Get-Culture).EnglishName
            If (($firefox_enumeration | select -ExpandProperty Locale) -ne $null) {
                $lang = [string]'&lang=' + ($firefox_enumeration | select -ExpandProperty Locale)
            } ElseIf (($firefox_enumeration | select -ExpandProperty Locale) -eq $null) {

                    If ((($language | Select-Object -ErrorAction SilentlyContinue -ExpandProperty "$($(Get-Culture).TwoLetterISOLanguageName)").English) -match ((Get-Culture).EnglishName.split(' (')[0]) ) {
                        $lang = [string]'&lang=' + $($(Get-Culture).TwoLetterISOLanguageName)
                    } ElseIf ((($language | Select-Object -ErrorAction SilentlyContinue -ExpandProperty "$($(Get-Culture).Name)").English) -match ((Get-Culture).EnglishName) ) {
                        $lang = [string]'&lang=' + $($(Get-Culture).Name)
                    } ElseIf ((($language | Select-Object -ErrorAction SilentlyContinue -ExpandProperty "$($(Get-Culture).Name)").English) -match ((Get-Culture).EnglishName.split(' (')[0]) ) {
                        $lang = [string]'&lang=' + $($(Get-Culture).Name)
                    } ElseIf ((($language | Select-Object -ErrorAction SilentlyContinue -ExpandProperty "$($(Get-Culture).TwoLetterISOLanguageName)").English) -match ((Get-Culture).EnglishName) ) {
                        $lang = [string]'&lang=' + $($(Get-Culture).TwoLetterISOLanguageName)
                    } Else {
                       $lang = [string]'&lang=' + (([Threading.Thread]::CurrentThread.CurrentUICulture).Name.Split("-")[0])
                     } # Else

            } Else {
                $continue = $true
            } # Else


    $download_url = [string]'https://download.mozilla.org/?product=firefox-latest' + $os + $lang


} ElseIf (($multiple_firefoxes -ne $true) -and ($admin_corner -eq $true)) {
    $continue = $true
} Else {
    Return "Multiple Firefox installations detected. Please update the relevant Firefox versions manually by visiting for example https://www.mozilla.org/en-US/firefox/all/ or run this script again after reducing the total number of Firefox installations to one. Exiting without updating (at Step 15)."
 }
If (($firefox_is_installed -eq $true) -and ($downloading_firefox_is_required -eq $true)) {

    $task_number = 4
    $task = "Downloading a full offline $bit_number-bit Firefox installer from $download_url"
    Write-Progress -Id $id -Activity $activity -Status $status -CurrentOperation $task -PercentComplete (($task_number / $total_steps) * 100)


    $download_file = "Firefox_Setup.exe"
    $firefox_save_location = "$path\$download_file"
    $firefox_is_downloaded = $false

    # Purge existing old Firefox installation files
    If ((Test-Path $firefox_save_location) -eq $true) {
        Write-Verbose "Deleting $firefox_save_location"
        Remove-Item -Path "$firefox_save_location"
    } Else {
        $continue = $true
    } # Else

            try
            {
                $download_firefox = New-Object System.Net.WebClient
                $download_firefox.DownloadFile($download_url, $firefox_save_location)
            }
            catch [System.Net.WebException]
            {
                Write-Warning "Failed to access $download_url"
                $empty_line | Out-String
                Return "Exiting without installing a new Firefox version (at Step 16)."
            }

    Start-Sleep -s 2

    If ((Test-Path $firefox_save_location) -eq $true) {
        $firefox_is_downloaded = $true
    } Else {
        $firefox_is_downloaded = $false
    } # Else

} Else {
    $continue = $true
}
$task_number = 8
$task = "Stopping Firefox -related processes..."
Write-Progress -Id $id -Activity $activity -Status $status -CurrentOperation $task -PercentComplete (($task_number / $total_steps) * 100)
Stop-Process -ProcessName '*messenger*' -ErrorAction SilentlyContinue -Force
Stop-Process -ProcessName 'FlashPlayer*' -ErrorAction SilentlyContinue -Force
Stop-Process -ProcessName 'plugin-container*' -ErrorAction SilentlyContinue -Force
Stop-Process -ProcessName 'chrome*' -ErrorAction SilentlyContinue -Force
Stop-Process -ProcessName 'opera*' -ErrorAction SilentlyContinue -Force
Stop-Process -ProcessName 'firefox' -ErrorAction SilentlyContinue -Force
Stop-Process -ProcessName 'iexplore' -ErrorAction SilentlyContinue -Force
Start-Sleep -s 4
$task_number = 11
$task = "Installing Firefox..."
Write-Progress -Id $id -Activity $activity -Status $status -CurrentOperation $task -PercentComplete (($task_number / $total_steps) * 100)
If ($firefox_is_downloaded -eq $true) {

    $task_number = 10
    $task = "Installing Firefox..."
    Write-Progress -Id $id -Activity $activity -Status $status -CurrentOperation $task -PercentComplete (($task_number / $total_steps) * 100)

    cd $path
    .\Firefox_Setup.exe /INI="$path\$ini_file" | Out-Null
    cd $script_path
    Start-Sleep -s 5
} Else {
    $continue = $true
}
$task_number = 15
$task = "Enumerating the Firefox versions found on the system after the update..."
Write-Progress -Id $id -Activity $activity -Status $status -CurrentOperation $task -PercentComplete (($task_number / $total_steps) * 100)
$firefox_is_installed = $false
If ((Check-InstalledSoftware "*Firefox*") -ne $null) {
    $firefox_is_installed = $true
} Else {
    $continue = $true
}
$32_bit_firefox_is_installed = $false
$64_bit_firefox_is_installed = $false
$registry_paths_after_update = Get-ItemProperty $registry_paths -ErrorAction SilentlyContinue | Where-Object { ($_.DisplayName -like "*Firefox*" ) -and ($_.Publisher -like "Mozilla*" )}
If ($registry_paths_after_update -ne $null) {

    ForEach ($new_firefox in $registry_paths_after_update) {

        # Custom Values
        If (($new_firefox.DisplayName.Split(" ")[-1] -match "\(") -eq $false) {
            $locale_new = ($new_firefox.DisplayName.Split(" ")[-1]).Replace(")","")
        } Else {
            $continue = $true
        } # Else


        If (($new_firefox.DisplayName.Split(" ")[-1] -match "\(x") -eq $true) {

            If ($new_firefox.DisplayName.Split(" ")[-1] -like "(x86")  {
                $32_bit_firefox_is_installed = $true
                $type_new = "32-bit"
            } ElseIf ($new_firefox.DisplayName.Split(" ")[-1] -like "(x64")  {
                $64_bit_firefox_is_installed = $true
                $type_new = "64-bit"
            } Else {
                $continue = $true
            } # Else

        } ElseIf (($new_firefox.DisplayName.Split(" ")[-2] -match "\(x") -eq $true) {

            If ($new_firefox.DisplayName.Split(" ")[-2] -like "(x86")  {
                $32_bit_firefox_is_installed = $true
                $type_new = "32-bit"
            } ElseIf ($new_firefox.DisplayName.Split(" ")[-2] -like "(x64")  {
                $64_bit_firefox_is_installed = $true
                $type_new = "64-bit"
            } Else {
                $continue = $true
            } # Else

        } Else {
            $continue = $true
        } # Else


        $product_version_new = ((Get-ItemProperty -Path "$($new_firefox.InstallLocation)\Firefox.exe" -ErrorAction SilentlyContinue -Name VersionInfo).VersionInfo).ProductVersion
        $regex_stability = $product_version_new -match "(\d+)\.(\d+)\.(\d+)"
        $regex_major = $product_version_new -match "(\d+)\.(\d+)"  
        If (($product_version_new -ne $null) -and ($regex_stability -eq $true)) { $product_version_new -match "(?<B1>\d+)\.(?<B2>\d+)\.(?<B3>\d+)" } Else { $continue = $true }
        If (($product_version_new -ne $null) -and ($regex_stability -eq $false) -and ($regex_major -eq $true))  { $product_version_new -match "(?<B1>\d+)\.(?<B2>\d+)" } Else { $continue = $true }


                            $after_update_firefoxes += $obj_updated_firefox = New-Object -TypeName PSCustomObject -Property @{
                                'Name'                          = $new_firefox.DisplayName.Replace("(TM)","")
                                'Publisher'                     = $new_firefox.Publisher
                                'Product'                       = $new_firefox.DisplayName.Split(" ")[1]
                                'Type'                          = $type_new
                                'Locale'                        = $locale_new
                                'Major Version'                 = If ($Matches.B1 -ne $null) { $Matches.B1 } Else { $continue = $true }
                                'Minor Version'                 = If ($Matches.B2 -ne $null) { $Matches.B2 } Else { $continue = $true }
                                'Build Number'                  = If ($Matches.B3 -ne $null) { $Matches.B3 } Else { "-" }
                                'Computer'                      = $computer
                                'Install Location'              = $new_firefox.InstallLocation
                                'Standard Uninstall String'     = $new_firefox.UninstallString.Trim('"')
                                'Release Notes'                 = $new_firefox.URLUpdateInfo
                                'Identifying Number'            = $new_firefox.PSChildName
                                'Version'                       = $new_firefox.DisplayVersion
                            } # New-Object
    } # foreach ($new_firefox)


        # Display the Firefox Version Enumeration in console
        If ($after_update_firefoxes -ne $null) {
            $after_update_firefoxes.PSObject.TypeNames.Insert(0,"Firefox Versions After the Update")
            $after_update_firefoxes_selection = $after_update_firefoxes | Select-Object 'Name','Publisher','Product','Type','Locale','Major Version','Minor Version','Build Number','Computer','Install Location','Standard Uninstall String','Release Notes','Version'
            $empty_line | Out-String
            $header_new = "Firefox Versions Found on the System After the Update"
            $coline_new = "-----------------------------------------------------"
            Write-Output $header_new
            $coline_new | Out-String
            Write-Output $after_update_firefoxes_selection
        } Else {
            $continue = $true
        } # Else

} Else {
    $continue = $true
}
$task_number = 16
$task = "Determining the success rate of the update process..."
Write-Progress -Id $id -Activity $activity -Status $status -CurrentOperation $task -PercentComplete (($task_number / $total_steps) * 100)
$multiple_firefoxes_after_update = $false
If ((($after_update_firefoxes | Measure-Object Name).Count) -eq 0) {
    $success = $false
    $empty_line | Out-String
    Write-Warning "No Firefox seems to be installed on the system."
    $empty_line | Out-String
    Return "The most recent non-beta Firefox version is $most_recent_firefox_version. This script tried to update Firefox, but something went wrong with the installation. Instead of updating Firefox this script uninstalled all versions of Firefox. Exiting at Step 20."
} ElseIf ((($after_update_firefoxes | Measure-Object Name).Count) -eq 1) {
   
    $continue = $true
} ElseIf ((($after_update_firefoxes | Measure-Object Name).Count) -ge 2) {
    $success = $false
    $empty_line | Out-String
    Write-Warning "More than one instance of Firefox seems to be installed on the system."
    $multiple_firefoxes_after_update = $true
    $empty_line | Out-String
    Return "The most recent non-beta Firefox version is $most_recent_firefox_version. This script tried to update Firefox, but something went wrong with the installation. Instead of updating Firefox this script installed yet another version of Firefox. Currently the versions $($after_update_firefoxes.Version) are installed. Exiting at Step 20."
} Else {
    $continue = $true
}
$most_recent_firefox_after_update = Check-InstalledSoftware "Mozilla Firefox $($most_recent_firefox_version)*"
If (($firefox_is_installed -eq $true) -and ($downloading_firefox_is_required -eq $true) -and ($after_update_firefoxes -ne $null) -and ($multiple_firefoxes_after_update -eq $false)) {

    If ($most_recent_firefox_after_update -eq $null) {
        $success = $false
        $empty_line | Out-String
        Write-Warning "Failed to update Mozilla Firefox"
        $empty_line | Out-String
        Return "$($after_update_firefoxes.Name) seems to be outdated. The most recent non-beta Firefox version is $most_recent_firefox_version. The installed Firefox version $($after_update_firefoxes.Version) needs to be updated. This script tried to update Firefox, but failed to do so."

    } ElseIf ($most_recent_firefox_after_update) {

        $success = $true
        $locale = If (($most_recent_firefox_after_update.DisplayName.Split(" ")[-1] -match "\(") -eq $false) {
                        If ($powershell_v2_or_earlier -eq $true) {
                            $language.Get_Item(($most_recent_firefox_after_update.DisplayName.Split(" ")[-1]).Replace(")",""))
                        } Else {
                            $language | Select-Object -ExpandProperty (($most_recent_firefox_after_update.DisplayName.Split(" ")[-1]).Replace(")",""))
                        } # Else

                    } Else {
                        $continue = $true
                    } # Else ($locale)

        If ($powershell_v2_or_earlier -eq $true) {
            try
            {
                $release_date = $all_dates.Get_Item($most_recent_firefox_after_update.DisplayVersion)
            }
            catch
            {
                $message = $error[0].Exception
                Write-Verbose $message
            }
        } Else {
            try
            {
                $release_date = $all_dates | Select-Object -ExpandProperty $most_recent_firefox_after_update.DisplayVersion
            }
            catch
            {
                $message = $error[0].Exception
                Write-Verbose $message
            }
       } # Else

                            $obj_success_firefox += New-Object -TypeName PSCustomObject -Property @{
                                'Name'                          = $most_recent_firefox_after_update.DisplayName.replace("(TM)","")
                                'Publisher'                     = $most_recent_firefox_after_update.Publisher
                                'Product'                       = $most_recent_firefox_after_update.DisplayName.Split(" ")[1]
                                'Type'                          = $after_update_firefoxes.Type
                                'Locale'                        = $locale
                                'Computer'                      = $computer
                                'Install_Location'              = $most_recent_firefox_after_update.InstallLocation
                                'Release Notes'                 = $most_recent_firefox_after_update.URLUpdateInfo
                                'Standard Uninstall String'     = $most_recent_firefox_after_update.UninstallString.Trim('"')
                                'Identifying Number'            = $most_recent_firefox_after_update.PSChildName
                                'Release_Date'                  = $release_date
                                'Version'                       = $most_recent_firefox_after_update.DisplayVersion

                            } # New-Object
                        $obj_success_firefox.PSObject.TypeNames.Insert(0,"Successfully Updated Firefox Version")

        $empty_line | Out-String
        Write-Output "Currently (until the next Firefox version is released) the $($($obj_success_firefox.Locale).English) $($obj_success_firefox.Type) $($obj_success_firefox.Name) released on $((Get-Date ($obj_success_firefox.Release_Date)).ToShortDateString()) doesn't need any further maintenance or care."
        $empty_line | Out-String
        Write-Output "The installed Firefox seems to be OK."

    } Else {
        $continue = $true
    } # Else

} Else {
    $continue = $true
}
$task_number = 17
$task = "Verifying that the Firefox has been installed by opening a web page in the default browser..."
Write-Progress -Id $id -Activity $activity -Status $status -CurrentOperation $task -PercentComplete (($task_number / $total_steps) * 100)
If ($obj_success_firefox -ne $null) {
    Start-Process -FilePath "$($obj_success_firefox.Install_Location)\firefox.exe" -ArgumentList "https://www.mozilla.org/en-US/firefox/new/"
} Else {
    $continue = $true
}
$task_number = 19
$task = "Finished updating Firefox."
Write-Progress -Id $id -Activity $activity -Status $status -CurrentOperation $task -PercentComplete (($task_number / $total_steps) * 100) -Completed
$end_time = Get-Date
$runtime = ($end_time) - ($start_time)
    If ($runtime.Days -ge 2) {
        $runtime_result = [string]$runtime.Days + ' days ' + $runtime.Hours + ' h ' + $runtime.Minutes + ' min'
    } ElseIf ($runtime.Days -gt 0) {
        $runtime_result = [string]$runtime.Days + ' day ' + $runtime.Hours + ' h ' + $runtime.Minutes + ' min'
    } ElseIf ($runtime.Hours -gt 0) {
        $runtime_result = [string]$runtime.Hours + ' h ' + $runtime.Minutes + ' min'
    } ElseIf ($runtime.Minutes -gt 0) {
        $runtime_result = [string]$runtime.Minutes + ' min ' + $runtime.Seconds + ' sec'
    } ElseIf ($runtime.Seconds -gt 0) {
        $runtime_result = [string]$runtime.Seconds + ' sec'
    } ElseIf ($runtime.Milliseconds -gt 1) {
        $runtime_result = [string]$runtime.Milliseconds + ' milliseconds'
    } ElseIf ($runtime.Milliseconds -eq 1) {
        $runtime_result = [string]$runtime.Milliseconds + ' millisecond'
    } ElseIf (($runtime.Milliseconds -gt 0) -and ($runtime.Milliseconds -lt 1)) {
        $runtime_result = [string]$runtime.Milliseconds + ' milliseconds'
    } Else {
        $runtime_result = [string]''
    } # Else (if)

        If ($runtime_result.Contains(" 0 h")) {
            $runtime_result = $runtime_result.Replace(" 0 h"," ")
            } If ($runtime_result.Contains(" 0 min")) {
                $runtime_result = $runtime_result.Replace(" 0 min"," ")
                } If ($runtime_result.Contains(" 0 sec")) {
                $runtime_result = $runtime_result.Replace(" 0 sec"," ")
        } # if ($runtime_result: first)
$empty_line | Out-String
$timestamp_end = Get-Date -Format hh:mm:ss
$end_text = "$timestamp_end - The Firefox Update Protocol completed."
Write-Output $end_text
$empty_line | Out-String
$runtime_text = "The update took $runtime_result."
Write-Output $runtime_text
$empty_line | Out-String
}

cls
switch (Read-Host -Prompt "Enable Automated Mode Y,[N]?") {
    Y {$a = 1}
    N {$a = 0}
    default {$a = 0}
}
if ($a -eq 0) {
    while ( $n -eq 0 ) {
    cls
    echo "╓─────Windows Update Script─────╖"
    echo "╠═══════════════════════════════╣"
    echo "╟ 1. Check for Updates          ║"
    echo "╟ 2. Download Updates           ║"
    echo "╟ 3. Install Updates            ║"
    echo "╟ 4. Reboot                     ║"
    echo "╚═══════════════════════════════╝"

        switch (Read-Host -Prompt "1,2,3,4") {
            1 {Get-WUList -Verbose}
            2 {Download-WindowsUpdate -AcceptAll -Verbose}
            3 {Install-WindowsUpdate -AcceptAll -Verbose -IgnoreReboot
               UpdateFirefox}
            4 {Restart-Computer -Confirm}
            default {echo "Error"}
        }
        switch (Read-Host -Prompt "Continue[Y],N?") {
            Y {$n = 0}
            N {$n = 1}
            default {$n = 0}
        }
    }
}
if ($a -eq 1) {
    Get-WUList -Verbose
    echo "Continue in 3 Seconds..."
    Start-Sleep -Seconds 3
    cls
    Download-WindowsUpdate -AcceptAll -Verbose
    echo "Continue in 3 Seconds..."
    Start-Sleep -Seconds 3
    cls
    Install-WindowsUpdate -AcceptAll -Verbose -IgnoreReboot
    UpdateFirefox
    echo "Continue in 3 Seconds..."
    Start-Sleep -Seconds 3
    cls
    Restart-Computer -Confirm
}