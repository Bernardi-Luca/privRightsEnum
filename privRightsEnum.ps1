###aggiungere if file non presenti, then scaricare estrarre e muovere

#WARNING: parameters are exclusive, specify only one
#if no parameters are specified, the script will perform all checks
param(
#checks for a user privilege on domain, if it's set the program won't run ACL checks
[string]$privtocheck="",
#checks for account privileges on domain objects, if it's set the program won't run user-on-domain checks
[string]$acltocheck=""
)

$isAcc=Test-Path -Path .\accesschk.exe -PathType Leaf
$isAD=Test-Path -Path .\Import-ActiveDirectory.ps1 -PathType Leaf

If ($isAcc -And $isAD){
echo 'AD module and accesschk in working dir, skipping download'
}
Else {
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
}

. .\Import-ActiveDirectory.ps1

#separator for output
$separator="==================================================================================================================================="


if($acltocheck){
}
else{

	#extracting domain users
	$users=Get-ADUser -filter * -properties * | ?{$_.Enabled -eq $true} | ForEach-Object{$dom=$_.CanonicalName.Split("/")[0]; $user=$_.SamAccountName; $dom,$user -join "\"}

	#extracting domain computers
	$computers=Get-ADComputer -filter * -properties * | ?{$_.Enabled -eq $true} | ForEach-Object{$dom=$_.CanonicalName.Split("/")[0]; $user=$_.SamAccountName; $dom,$user -join "\"}

	echo '!!!!!user privileges and rights on the domain!!!!!'	

	if($privtocheck){
		foreach($user in $users){
			$out=.\accesschk.exe $user /accepteula -s -q -a * | select -skip 5 | findstr.exe $privtocheck
			if($out){
				echo $separator
				$user,$privtocheck -join '-->'
			}
			$out=''
		}
	}
	else{
		foreach($user in $users){
			echo $separator
			echo $user
			.\accesschk.exe $user /accepteula -s -q -a * | select -skip 5
		}
	}
	
	echo ''
	echo $separator
	echo $separator
	echo $separator
	echo ''
	echo '!!!!!computer privileges and rights on the domain!!!!!'
	
	if($privtocheck){
		foreach($computer in $computers){
			$out=.\accesschk.exe $user /accepteula -s -q -a * | select -skip 5 | findstr.exe $privtocheck
			if($out){
				echo ''
				echo $separator
				echo $separator
				echo $separator
				echo ''
				echo '!!!!!computer privileges and rights on the domain!!!!!'

				echo $separator
				$computer,$privtocheck -join '-->'
			}
			$out=''
		}
	}
	else{
		foreach($computer in $computers){

			echo $separator
			echo $computer
			.\accesschk.exe $user /accepteula -s -q -a * | select -skip 5
		}
	}

}

if($privtocheck){
}
else{

	echo ''
	echo $separator
	echo $separator
	echo $separator
	echo ''	

	#extracting domain users DN
	$userDNs=Get-ADUser -filter * -properties * | ?{$_.Enabled -eq $true} | select -ExpandProperty DistinguishedName

	#extracting domain computer DNs
	$computerDNs=Get-ADComputer -filter * -properties * | ?{$_.Enabled -eq $true} | select -ExpandProperty DistinguishedName

	echo '!!!!!User privileges and rights on each AD object!!!!!'

	$ADString='AD:'

	#extracting user privileges and rights for users







	if($acltocheck){
		foreach($userDN in $userDNs){
			$userDN=$ADString+$userDN
			$out=Get-Acl $userDN | select -ExpandProperty Access | ForEach-Object{$acc=$_.IdentityReference; $rights=$_.ActiveDirectoryRights; $acc,$rights -join "-->"} | findstr.exe $acltocheck
			if($out){
				echo $separator
				echo $userDN
				echo $out
			}
			$out=''
		}
	}
	else{
		foreach($userDN in $userDNs){
			$userDN=$ADString+$userDN
			echo $separator
			echo $userDN
			Get-Acl $userDN | select -ExpandProperty Access | ForEach-Object{$acc=$_.IdentityReference; $rights=$_.ActiveDirectoryRights; $acc,$rights -join "-->"}
		}
	}
	echo ''
	echo $separator
	echo $separator
	echo $separator
	echo ''

	echo '!!!!!Computer privileges and rights on each AD object!!!!!'

	#extracting user privileges and rights for computers
	if($acltocheck){
		foreach($computerDN in $computerDNs){
			$computerDN=$ADString+$computerDN
			$out=Get-Acl $computerDN | select -ExpandProperty Access | ForEach-Object{$acc=$_.IdentityReference; $rights=$_.ActiveDirectoryRights; $acc,$rights -join "-->"} | findstr.exe $acltocheck
			if($out){
				echo $separator
				echo $computerDN
				echo $out
			}
			$out=''
		}
	}
	else{
		foreach($computerDN in $computerDNs){
			$computerDN=$ADString+$computerDN
			echo $separator
			echo $computerDN
			Get-Acl $computerDN | select -ExpandProperty Access | ForEach-Object{$acc=$_.IdentityReference; $rights=$_.ActiveDirectoryRights; $acc,$rights -join "-->"}
		}
	}
}
