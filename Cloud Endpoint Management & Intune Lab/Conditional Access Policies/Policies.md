
CA001 Block legacy auth. All users, all apps, block. Legacy protocols skip MFA. Kill them first.

CA002 Require MFA for all users. Baseline. All apps.

CA100 Phishing-resistant MFA for admins. Grant = auth strength: phishing-resistant (FIDO2 / Windows Hello). No push. Stops MFA fatigue on privileged accounts.

CA200 Require compliant device. All users, all resources. Ties Intune compliance to access.

CA400 Block untrusted locations. Named locations for expected countries, block the rest.

CA500 Require app protection policy on mobile. Threat: corporate data leaking off unmanaged phones.