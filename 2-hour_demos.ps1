
#region IMPROVE POWERSHELL EXPERIENCE IN WINDOWS TERMINAL AND VISUAL STUDIO CODE

# https://ohmyposh.dev/
# https://ohmyposh.dev/docs/upgrading/

# https://www.nerdfonts.com/font-downloads
# Caskaydia Code Nerd Font
# For PowerShell console, change a font in Properties
# For Visual Studio Code, go to Settings > Terminal > Integrated: Font Family 'CaskaydiaCove NF'

Install-Module -Name posh-git, oh-my-posh, Terminal-Icons -Repository PSGallery

# Add to $PROFILE file
Import-Module posh-git
Import-Module oh-my-posh
Import-Module Terminal-Icons
# Set-Theme Paradox (v2-way)
Set-PoshPrompt -Theme jandedobbeleer

#endregion

#region STOP STORING ENCRYPTED CREDENTIALS IN YOUR POWERSHELL SCRIPTS

# How we used to do it
# Encrypt an exported credential object on Windows

# The Export-Clixml cmdlet encrypts credential objects by using the Windows Data Protection API.
# The encryption ensures that only your user account on only that computer can decrypt the contents of the credential object.
# The exported CLIXML file can't be used on a different computer or by a different user.

$Credential = Get-Credential
$Credxmlpath = Join-Path (Split-Path $Profile) TestScript.ps1.credential
$Credential | Export-Clixml $Credxmlpath
Get-Content $Credxmlpath

# Later, in TestScript.ps1, you recreate the credentials
$Credxmlpath = Join-Path (Split-Path $Profile) TestScript.ps1.credential
$Credential = Import-Clixml $Credxmlpath

# Export-Clixml only exports encrypted credentials on Windows.
# On non-Windows operating systems such as macOS and Linux, credentials are exported as a plain text
# stored as a Unicode character array. This provides some obfuscation but does not provide encryption.

# Start PowerShell on Linux (WSL)
$Credential = Get-Credential

$Credential | Export-Clixml ./credentials.xml
Get-Content ./credentials.xml

#  The value is encoded but not encrypted
$Credential.GetNetworkCredential().Password | Format-Hex -Encoding unicode

# The author of these amazing code snippets is Tobias Weltner (@TobiasPSP) 
-join ([Text.Encoding]::Unicode.GetBytes('SuperSecret') | ForEach-Object { [Convert]::ToString($_, 16).PadLeft(2,'0')})

$bytes = '53007500700065007200530065006300720065007400' -split '(?<=\G.{2})(?=.)' | ForEach-Object { [Convert]::ToByte($_, 16)}
[Text.Encoding]::Unicode.GetString($bytes)

[Text.Encoding]::Unicode.GetString((-split ('53007500700065007200530065006300720065007400' -replace '..', '0x$& ')) -as [byte[]])

# SecretManagement and SecretStore

Install-Module Microsoft.PowerShell.SecretManagement

# The SecretManagement module provides the following cmdlets for accessing secrets and managing SecretVaults

Get-Command -Module Microsoft.PowerShell.SecretManagement | Sort-Object noun | Format-Table -GroupBy noun

# SecretManagement becomes useful once you install and register extension vaults.
# Extension vaults, which are PowerShell modules with a particular structure,
# provide the connection between the SecretManagement module and any local or remote Secret Vault.
Find-Module -Tag "SecretManagement" -Repository PSGallery

Install-Module Microsoft.PowerShell.SecretStore

# The SecretStore vault stores secrets locally on file for the current user,
# and uses .NET Core cryptographic APIs to encrypt file contents. 
Get-Command -Module Microsoft.PowerShell.SecretStore | Sort-Object noun | Format-Table -GroupBy noun

# Getting started with SecretStore

Register-SecretVault -Name MySecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
Get-SecretStoreConfiguration

Set-Secret -Name DemoSecret -Secret "SuperSecret"
Get-Secret -Name DemoSecret
Get-Secret -Name DemoSecret -AsPlainText

# To see the names all of your secrets
Get-SecretInfo -Vault MySecretStore
Set-SecretInfo -Name DemoSecret -Vault MySecretStore -Metadata @{Purpose = "A password for demos"}
Get-SecretInfo -Vault MySecretStore | Format-Table *

<# Using the SecretStore in Automation
$password = Import-CliXml -Path $securePasswordPath

Set-SecretStoreConfiguration -Scope CurrentUser -Authentication Password -PasswordTimeout 3600 -Interaction None -Password $password -Confirm:$false

Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault

Unlock-SecretStore -Password $password
#>

Get-Command -Module SecretManagement.Chromium | Sort-Object noun | Format-Table -GroupBy noun

# Getting Started with Azure Key Vault
$azKeyVault = Get-AzKeyVault -Name githubkv
$vaultName = ($azKeyVault.ResourceId -split '/')[-1]
$subID = ($azKeyVault.ResourceId -split '/')[2]

Register-SecretVault -Module Az.KeyVault -Name AzKV -VaultParameters  @{ AZKVaultName = $vaultName; SubscriptionId = $subID}

Get-SecretInfo -Vault AzKV
Get-Secret -Name PATforCloudShell -Vault AzKV
#endregion

#region SAVE YOUR POWERSHELL COMMANDS TOGETHER WITH THEIR RESULTS, AND SHARE IT WITH OTHERS

# PowerShell notebooks!
# .NET Interactive notebooks in Visual Studio Code and Azure Data Studio support PowerShell

cd C:\gh\notebooks && Show-Repo

# Install GitHub CLI from https://cli.github.com/
# function Show-Repo { gh repo view --web }

#endregion

#region LET POWERSHELL HELP AND TELL YOU WHAT TO TYPE

# Windows PowerShell

Find-Module psreadline -AllowPrerelease
Install-Module psreadline -AllowPrerelease -Scope CurrentUser -Verbose
# Install-Module psreadline -AllowPrerelease -Scope CurrentUser -Verbose -Force

# When the cursor is at the end of a fully expanded cmdlet, pressing F1 displays the help for that cmdlet.
# When the cursor is at the end of a fully expanded parameter, pressing F1 displays the help beginning at the parameter.
# Pressing the Alt+h key combination provides dynamic help for parameters.

# Set-PSReadLineKeyHandler -chord "Ctrl+l" -Function ShowParameterHelp

Get-PSReadLineKeyHandler | where function -match help

# Press Alt+a to rapidly select and change the arguments of a command

Invoke-Command -ComputerName Server1 -ScriptBlock {Get-Service -Name win* -OutVariable services} -SessionName $so

# An example profile for PSReadLine
psedit (Join-Path (Split-Path (Get-Module psreadline).Path) SamplePSReadLineProfile.ps1)

# Predictive IntelliSense
# matching predictions from the user’s history and additional domain specific plugins

Set-PSReadLineOption -PredictionSource History

Get-PSReadLineOption | fl *prediction*
Get-PSReadLineOption

# The default light-grey prediction text color
Set-PSReadLineOption -Colors @{ InlinePrediction = "$([char]0x1b)[48;5;238m"}

Set-PSReadLineOption -Colors @{ InlinePrediction = '#8A0303'}
Set-PSReadLineOption -Colors @{ InlinePrediction = '#2F7004'}
Set-PSReadLineOption -Colors @{ InlinePrediction = "$([char]0x1b)[36;7;238m"}

# By default, pressing RightArrow accepts an inline suggestion when the cursor is at the end of the current line.

# Predictions are displayed in one of two views depending on the user preference

# InlineView – This is the default view and displays the prediction inline with the user’s typing. This view is similar to other shells Fish and ZSH.
# ListView – ListView provides a dropdown list of predictions below the line the user is typing.

# You can change the view at the command line using the keybinding F2 or
# Set-PSReadLineOption -PredictionViewStyle ListView

# Start PowerShell 7.2 Preview and show Az Predictor (use Windows Terminal)

#endregion

#region VARIOUS POWERSHELL TIPS AND TRICKS

<# Launch Regedit at a specific location from the command line (regedit-dot.ps1)
   @Lee_Holmes

function regedit. {
    $currentPath = Get-Item . | ForEach-Object Name
    $launchLocation = "COMPUTER\$currentPath"
    Set-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit -Name LastKey -Value $launchLocation
    regedit
}

#>

cd HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion
regedit.

<#
Was talking to a friend about Perf Counters today, and it's incredible how much data is at our fingertips in Windows.
Here's a trivial example of finding out which process is currently consuming the most disk I/O.
# @Lee_Holmes
#>

(Get-Counter -Counter "\Process(*)\IO Data Bytes/sec" -ErrorAction Ignore).CounterSamples |
Sort-Object -Descending CookedValue | Select-Object -First 10

# Splatting

# @duckgoop
$query = "select * from table where name = 'user'"
$invokeSqlCmdSplat = @{
    ServerInstance = 'ServerName'
    Database   = 'MyDB'
    Query        = $query
}
Invoke-SqlCmd @invokeSqlCmdSplat

# Use some long command and show splatting in VSCode Insiders (I have an older version of PS extension there)
Get-Command -Module SecretManagement -CommandType Cmdlet -Verbose

# @REOScotte
hostname | clip

# @mbsnl
function Connect-MyAzureAD { 
    Connect-AzureAD -AadAccessToken (Get-AzAccessToken -ResourceUrl https://graph.windows.net).token -AccountId (Get-AzContext).Account.Id -TenantId (Get-AzContext).Tenant.Id | Out-Null 
}

# @JustinWgrote
# using [version] to sort IP addresses by octet :)
[string[]]('222.1.3.4','1.2.3.4' | ForEach-Object {[Version]$_} | Sort-Object)

# @rjmholt
# I like to abuse the fact that @(...) will flatten a series of statements
# into an array to conditionally add array entries without lists or +=. 
# Example 1

$statArgs = @(
    '-c'
    if ($IsMacOS) { '%A' } else { '%a' }
    '/etc/passwd'
)

# Also note that this is an example of array splatting with a native command
/bin/stat @statArgs

# Example 2

# Naturally this is a bit contrived, since you could do gci ./PowerShell,./WindowsPowerShell with some extra logic
$FilesToCopy = @(
    Get-ChildItem -Path ~/Documents/PowerShell -Recurse -Filter '*.json.xml'
    if (Test-Path -Path ~/Documents/WindowsPowerShell) { Get-ChildItem -Path ~/Documents/WindowsPowerShell -Recurse -Filter '*.json.xml' }
)

# @sassdawe
$Array[6..8]

$Array[-1]

# Variables

'Hello, PowerShellers!' > TEMP:\hello.txt
Get-Content TEMP:\hello.txt
${TEMP:\hello.txt}
${function:help}

# @ProfessorLogout
$PSDefaultParameterValues.Add("*:Verbose", {$verbose -eq $true})

# @JustinWGrote
# I've become very partial to:

$item1,$item2 = $arrayoftwoitems

$email = 'aleksandar@gmail.com'
$user,$domain = $email.split('@')

$first,$second,$therest = $array

# @IISResetMe
# You can swap variable values with a single assignment
$a,$b = $b,$a

# Quick way to create a test array
,"powershell"*7

# @deadlydog
# When still using PS5, include this before any web requests.
# Many websites block TLS 1.0 and 1.1 now, including the PSGallery,
# so your requests will fail, often with a non-obvious error message.

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# @ryanyates1990
# Inline command execution like this which is really nifty when running interactively
Invoke-Command -ComputerName (Get-content C .\comp.txt) -Credential (Get-credential)

# @PrzemyslawKlys
# Speedy hash tables
$UsersAll = Get-ADUser -Properties Manager, DisplayName, EmailAddress -Filter '*'
# This time we will prepare Hashtable that will keep DistinguishedName as a key
$Optimize = @{}
foreach ($item in $UsersAll) {
    $Optimize[$item.DistinguishedName] = $item
}
# End of preparations

$UsersWithManagers = foreach ($User in $UsersAll) {
    if ($null -ne $User.Manager) {
        $Manager = $Optimize[$User.Manager]
    } else {
        $Manager = $null
    }
    [PSCustomobject] @{
        SamAccountName = $User.SamAccountName
        Manager        = $User.Manager
        ManagerDisplay = $Manager.DisplayName
        ManagerEmail   = $Manager.EmailAddress
    }
}
$UsersWithManagers | Format-Table -AutoSize

Measure-Command {$a = @{}; 1..10000 | ForEach-Object {$a.$_ = $_}}

Measure-Command {$b = @{}; 1..10000 | ForEach-Object {$b.add($_, $_)}}

Measure-Command {$c = @{}; 1..10000 | ForEach-Object {$c[$_] = $_}}

Measure-Command {
    $b = @{}
    for ($i = 1; $i -le 10000; $i++) {

        $b.add($i, $i)
    }
}

#endregion









