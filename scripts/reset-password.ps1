param (
    [string]$Username,
    [string]$PlainPassword
)

Import-Module ActiveDirectory

$newPassword = ConvertTo-SecureString $PlainPassword -AsPlainText -Force

try {
    $user = Get-ADUser -Identity $Username -ErrorAction Stop

    Set-ADAccountPassword -Identity $Username -NewPassword $newPassword -Reset
    Set-ADUser -Identity $Username -ChangePasswordAtLogon $false

    Write-Host "✅ Password user '$Username' berhasil diubah." -ForegroundColor Green
} catch {
    Write-Host "❌ Gagal mengubah password: $_" -ForegroundColor Red
}
