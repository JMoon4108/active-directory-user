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

#Lets user choose the OU 
Function Get-ou-path {
    $ouList = Get-ADOrganizationalUnit -Filter *

    $selectedOU = $ouList | Out-GridView -Title "Select an OU" -OutputMode Single

    if ($selectedOU) {
        Write-Host "$selectedOU selected"
    }
    return $selectedOU.DistinguishedName
}

#collect new user information
$firstName = Read-Host -Prompt "Enter first name"
$lastName = Read-Host -Prompt "Enter last name"
$username = Read-Host -Prompt "Enter Username"
$ouPath = Get-ou-path

#group selection
$selectedGroup = $(Get-ADGroup -Filter * | Sort-Object Name) | Out-GridView -Title "Please select a group for permissions" -OutputMode Single

$newPassword = Set-random-password
$securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force

#Return password and username to command prompt, to provide to user
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


#prompt for password change on first login (Allows for RDP login for first time)
Set-ADUser -Identity $username -Replace @{pwdLastSet=0}

#assign group
Add-ADGroupMember -Identity "$selectedGroup" -Members "$username"

Get-ADUser 
