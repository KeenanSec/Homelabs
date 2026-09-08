Here is the in-depth version, structured as you click through it.

## 1. Create the policy

Intune admin center > Devices > Compliance > Create policy > Platform: Windows 10 and later. Name it clearly, for example `COMP-Win11-Baseline`.

![[Pasted image 20260907032220.png]]


![[Pasted image 20260907032430.png]]
## 2. Device Health

- Require BitLocker: Require
- Require Secure Boot: Require
- Require code integrity: Require

![[Pasted image 20260907032541.png]]

## 3. Device Properties

- Minimum OS version: enter full version and build, format `10.0.26100.xxxx` (Win11 24H2 is build 26100). Set it to your current patch level so unpatched devices fail.
- Maximum OS version: leave blank unless you want to block preview builds.
- Valid operating system builds: optional table if you want to allow only specific builds.


![[Pasted image 20260907032711.png]]
## 4. System Security, password

- Require password to unlock: Require
- Simple passwords: Block
- Password type: Alphanumeric
- Password Complexity: Require digits, lowercase, uppercase, and special characters
- Minimum length: 8 
- Max minutes of inactivity before password: 15
- Password expiration (days): 41 to 365, or leave off if you follow modern no-expiry guidance
- Prevent reuse of previous passwords: 5

![[Pasted image 20260907033203.png]]
## 5. System Security, device security

- Firewall: Require
- TPM: Require
- Antivirus: Require
- Antispyware: Require
- Encryption of data storage: Require

![[Pasted image 20260907033526.png]]
## 6. System Security, Defender

- Microsoft Defender Antimalware: Require
- Real-time protection: Require
- Security intelligence up to date: Require
- Minimum Defender version: optional, set if you want version enforcement

![[Pasted image 20260907033616.png]]


![[Pasted image 20260907033757.png]]

Then Select `Next`

## 7. Actions for noncompliance

- Mark device noncompliant: schedule `1 day` grace, not 0. Zero flags transient states as failures.
- Send email to end user: create a notification message template first, then attach it. Option to CC managers.
- Remotely lock the noncompliant device: optional, add for realism.
- Retire the noncompliant device: optional, set to a high day count like 30 so you do not nuke test devices by accident.

![[Pasted image 20260907034726.png]]
## 8. Assignments

- Included groups: your device or user security group.
- Excluded groups: your break-glass admin group.

![[Pasted image 20260907035439.png]]

## 9. Tenant setting, fail closed

Devices > Compliance > Compliance policy settings.

- Mark devices with no compliance policy assigned as: Not compliant
- Compliance status validity period (days): 30


![[Pasted image 20260907035637.png]]
## Depth notes

- BitLocker required here plus your BitLocker config profile means one enforces, one verifies. Show both.
- Grace period matters. Explain in your writeup why 1 day beats 0.
- Fail closed is the key enterprise choice. Document that unmanaged devices are denied by default, and that Conditional Access reads this compliance state.

Want the notification message template wording and the exact break-glass exclusion setup next?