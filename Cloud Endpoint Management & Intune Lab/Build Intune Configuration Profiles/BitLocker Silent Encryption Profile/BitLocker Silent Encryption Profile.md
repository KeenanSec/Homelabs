`https://intune.microsoft.com/#home`


![](Pasted%20image%2020260902030922.png)


### Basic

![](Pasted%20image%2020260902031048.png)



### Configuration Settings

## Phase 3 Appendix: BitLocker Disk Encryption Profile — As-Deployed Settings

### BitLocker

| Setting | Value |
|---|---|
| Require Device Encryption | Enabled |
| Allow Warning For Other Disk Encryption | Enabled (Default) |
| Configure Recovery Password Rotation | Not configured |

### BitLocker Drive Encryption

| Setting | Value |
|---|---|
| Choose drive encryption method and cipher strength | Enabled |
| Encryption method — OS drives | XTS-AES 256-bit |
| Encryption method — fixed data drives | XTS-AES 256-bit |
| Encryption method — removable data drives | XTS-AES 256-bit |
| Provide unique identifiers for your organization | Not configured |

### Operating System Drives

| Setting | Value |
|---|---|
| Choose how BitLocker-protected OS drives can be recovered | Enabled |
| Save BitLocker recovery information to AD DS | True |
| Do not enable BitLocker until recovery information is stored to AD DS | True |
| Configure user storage of BitLocker recovery information | Allow 48-digit recovery password |
| Allow data recovery agent | True |
| Configure storage of BitLocker recovery information to AD DS | Store recovery passwords only |
| Omit recovery options from the BitLocker setup wizard | True |
| OS recovery key usage | Allow 256-bit recovery key |
| Configure pre-boot recovery message and URL | Enabled (Default) |
| PIN / startup authentication settings | Not configured |

### Fixed Data Drives / Removable Data Drives

| Setting | Value |
|---|---|
| All fixed data drive settings | Not configured |
| All removable data drive settings | Not configured |


### Assignments

I assigned the `SG-Secured-Endpoints` and select `Next`

![](Pasted%20image%2020260902033017.png)


Select `Create`

![](Pasted%20image%2020260902033115.png)