###aggiungere if file non presenti, then scaricare estrarre e muovere

Invoke-WebRequest 'https://download.sysinternals.com/files/AccessChk.zip' -OutFile 'AccessChk.zip'
Invoke-WebRequest 'https://github.com/samratashok/ADModule/archive/refs/heads/master.zip' -OutFile 'ADModule.zip'

Expand-Archive 'AccessChk.zip'
Expand-Archive 'ADModule.zip'

move .\ADModule\ADModule-master\* .
move .\AccessChk\* .

rm .\ADModule\ -Recurse
rm .\AccessChk\ -Recurse
rm AccessChk.zip
rm ADModule.zip

. .\Import-ActiveDirectory.ps1

#separator for output
$separator="==================================================================================================================================="

#extracting domain users
$users=Get-ADUser -filter * -properties * | ?{$_.Enabled -eq $true} | ForEach-Object{$dom=$_.CanonicalName.Split("/")[0]; $user=$_.SamAccountName; $dom,$user -join "\"}

#extracting domain computers
$computers=Get-ADComputer -filter * -properties * | ?{$_.Enabled -eq $true} | ForEach-Object{$dom=$_.CanonicalName.Split("/")[0]; $user=$_.SamAccountName; $dom,$user -join "\"}

echo '!!!!!user privileges and rights on the domain!!!!!'
foreach($user in $users){echo $separator; echo $user; .\accesschk.exe $user /accepteula -s -q -a * | select -skip 5}

echo ''
echo $separator
echo $separator
echo $separator
echo ''

echo '!!!!!computer privileges and rights on the domain!!!!!'
foreach($computer in $computers){echo $separator; echo $computer; .\accesschk.exe $user /accepteula -s -q -a * | select -skip 5}


#extracting domain users DN
$userDNs=Get-ADUser -filter * -properties * | ?{$_.Enabled -eq $true} | select -ExpandProperty DistinguishedName

#extracting domain computer DNs
$computerDNs=Get-ADComputer -filter * -properties * | ?{$_.Enabled -eq $true} | select -ExpandProperty DistinguishedName

echo ''
echo $separator
echo $separator
echo $separator
echo ''

echo '!!!!!User privileges and rights on each AD object!!!!!'

$ADString='AD:'

#extracting user privileges and rights on users
foreach($userDN in $userDNs){$userDN=$ADString+$userDN;echo $separator; echo $userDN; Get-Acl $userDN | select -ExpandProperty Access | ForEach-Object{$acc=$_.IdentityReference; $rights=$_.ActiveDirectoryRights; $acc,$rights -join "-->"}}

echo ''
echo $separator
echo $separator
echo $separator
echo ''

echo '!!!!!Computer privileges and rights on each AD object!!!!!'

#extracting user privileges and rights on computers
foreach($computerDN in $computerDNs){$computerDN=$ADString+$computerDN;echo $separator; echo $computerDN; Get-Acl $computerDN | select -ExpandProperty Access | ForEach-Object{$acc=$_.IdentityReference; $rights=$_.ActiveDirectoryRights; $acc,$rights -join "-->"}}
