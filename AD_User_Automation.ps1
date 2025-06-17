Import-Module ActiveDirectory
Set-StrictMode -Version latest

#generates a random password that complies with the AD password requirements
Function Set-random-password() {
    $specialChars = @('!','?','&','@','#','%','^','*','$')
    $Chars = @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z')
    $numbers = @('1','2','3','4','5','6','7','8','9','0')

    $passwordChars = @()
    $passwordChars += $specialChars | Get-Random
    $passwordChars += $numbers | Get-Random
    $passwordChars += $Chars | Get-Random -Count 5

    $password = ($passwordChars) -join''
    
    return $password

}

#OU selection using GUI 
Function Get-ou-path {
    $ouList = Get-ADOrganizationalUnit -Filter *

    $selectedOU = $ouList | Out-GridView -Title "Select an OU" -OutputMode Single

    if ($selectedOU) {
        Write-Host "$selectedOU selected"
    }
    return $selectedOU.DistinguishedName
}
#validate name entry
Function Get-valid-name {
    param(
        [string]$namePrompt = ""
    )
    do{
        $isValid = $false
        try{
            $userInput = Read-Host $namePrompt

            if ([string]::IsNullOrWhiteSpace($userInput)){
                throw "Please enter a name."
            }

            if ($userInput -notmatch '^[a-zA-z-]+$'){
                throw "Please enter a name with only numbers or hyphens."
            }
            $isValid = $true
        }
        catch{
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    } until ($isValid)
    return $userInput
}
#validate username entry
Function Get-valid-username {
    do{
        $isValid = $false
        try{
            $username = Read-Host -Prompt "Enter Username"

            if ([string]::IsNullOrWhiteSpace($username)){
                throw "Please enter a username."
            }

            if ($username -notmatch '^[a-zA-Z0-9-.]+$'){
                throw "Please use valid characters: (A-Z), (a-z), (0-9), '-', '.'"
            }

            if ($username[-1] -match '\.$'){
                throw "Please enter a username that doesn't end with a period."
            }

            $isValid = $true
        }
        catch{
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    } until ($isValid)
    return $username
}

#collect new user information
$firstName = Get-valid-name "Enter first name"
$lastName = Get-valid-name "Enter last name"
$username = Get-valid-username
$ouPath = Get-ou-path

#group selection using GUI
$selectedGroup = $(Get-ADGroup -Filter * | Sort-Object Name) | Out-GridView -Title "Please select a group for permissions" -OutputMode Single

$newPassword = Set-random-password
$securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force

#return password and username to command prompt, to provide to user
Write-Host "Creating User: $($username)" -BackgroundColor Black -ForegroundColor Cyan
Write-Host "With password: $newPassword" -BackgroundColor Black -ForegroundColor Cyan

#Create users and configure settings for user
New-AdUser  -AccountPassword $SecurePassword `
            -GivenName $firstName `
            -Surname $lastName `
            -DisplayName "$firstname $lastName" `
            -Name "$firstname $lastName" `
            -SamAccountName $username `
            -EmployeeID $username `
            -ChangePasswordAtLogon $false `
            -PasswordNeverExpires $false `
            -Enabled $true `
            -Path "$ouPath" 


#prompt for password change on first login (allows for RDP login for first time)
Set-ADUser -Identity $username -Replace @{pwdLastSet=0}

#assign group and permissions
Add-ADGroupMember -Identity "$selectedGroup" -Members "$username"

