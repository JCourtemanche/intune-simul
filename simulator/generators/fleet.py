"""
Deterministic Intune fleet for Business Corp.

- The 6 shared personas (xsiam-shared-personas) are enrolled on VULNERABLE OS builds
  matching the Exposure Management hero cases (e.g. CVE-2024-38063 on Windows,
  CVE-2023-42917 on macOS / iOS).
- Filler devices are already patched, so the dashboard shows a realistic, mostly
  compliant fleet with a few devices to remediate.
- Servers (srv-*.business.org) are deliberately NOT enrolled: Intune manages the
  user fleet, not servers.
"""
import random
import uuid
from datetime import datetime, timedelta, timezone

from faker import Faker
from xsiam_shared import DOMAIN, USERS

SEED = 4242

# OS release trains: vulnerable build -> patched build delivered by the remediation policy.
# Builds are the real public ones (July 2024 -> August 2024 cumulative updates for Windows).
OS_TRAINS = {
    'win10_22h2': {
        'operatingSystem': 'Windows', 'label': 'Windows 10 Pro 22H2',
        'vulnerable': '10.0.19045.4651', 'patched': '10.0.19045.4780',
        'update': 'KB5041580 - 2024-08 Cumulative Update for Windows 10 22H2',
    },
    'win11_23h2': {
        'operatingSystem': 'Windows', 'label': 'Windows 11 Pro 23H2',
        'vulnerable': '10.0.22631.3880', 'patched': '10.0.22631.4037',
        'update': 'KB5041585 - 2024-08 Cumulative Update for Windows 11 23H2',
    },
    'macos_sonoma': {
        'operatingSystem': 'macOS', 'label': 'macOS 14 Sonoma',
        'vulnerable': '14.1.1', 'patched': '14.1.2',
        'update': 'macOS Sonoma 14.1.2 (WebKit security fix)',
    },
    'macos_ventura': {
        'operatingSystem': 'macOS', 'label': 'macOS 13 Ventura',
        'vulnerable': '13.6.1', 'patched': '13.6.3',
        'update': 'macOS Ventura 13.6.3 + Safari 17.1.2',
    },
    'ios_17': {
        'operatingSystem': 'iOS', 'label': 'iOS 17',
        'vulnerable': '17.1.1', 'patched': '17.1.2',
        'update': 'iOS 17.1.2 (WebKit security fix)',
    },
    'android_14': {
        'operatingSystem': 'Android', 'label': 'Android 14',
        'vulnerable': '14', 'patched': '14',
        'update': 'Android security patch level 2024-08-01',
    },
}

PERSONA_TRAIN = {
    'BSNS-WIN-ALICE': 'win10_22h2',
    'BSNS-WIN-CHARLIE': 'win11_23h2',
    'BSNS-WIN-DAVID': 'win10_22h2',
    'BSNS-MAC-BOB': 'macos_ventura',
    'BSNS-MAC-EMMA': 'macos_sonoma',
    'BSNS-MOB-FLORA': 'ios_17',
}

HARDWARE = {
    'Windows': [('Dell Inc.', 'Latitude 7440'), ('Lenovo', 'ThinkPad T14 Gen 4'), ('HP', 'EliteBook 840 G10'),
                ('Dell Inc.', 'OptiPlex 7010')],
    'macOS': [('Apple', 'MacBook Pro (14-inch, 2023)'), ('Apple', 'MacBook Air (M2, 2022)')],
    'iOS': [('Apple', 'iPhone 15'), ('Apple', 'iPhone 14 Pro')],
    'Android': [('samsung', 'Galaxy S23'), ('Google', 'Pixel 8')],
}

# Remediation groups targeted in Intune by an update policy. XSIAM only adds the device
# to the right group; Intune does the patching with policies the customer already owns.
REMEDIATION_GROUPS = [
    {
        'key': 'windows', 'operatingSystem': 'Windows',
        'displayName': 'XSIAM-Remediation-Windows-Expedite',
        'description': 'Devices that must receive the latest Windows security update immediately '
                       '(targeted by the expedited quality update profile).',
        'policy': 'XSIAM - Expedite latest Windows security update',
    },
    {
        'key': 'macos', 'operatingSystem': 'macOS',
        'displayName': 'XSIAM-Remediation-macOS-Update',
        'description': 'Macs that must install the latest macOS security update (DDM software update policy).',
        'policy': 'XSIAM - Enforce latest macOS security update',
    },
    {
        'key': 'ios', 'operatingSystem': 'iOS',
        'displayName': 'XSIAM-Remediation-iOS-Update',
        'description': 'iPhones / iPads that must install the latest iOS security update.',
        'policy': 'XSIAM - Enforce latest iOS security update',
    },
]

OTHER_GROUPS = [
    ('Intune - All Corporate Windows Devices', 'All company-owned Windows devices'),
    ('Intune - All Corporate Macs', 'All company-owned Macs'),
    ('Intune - Mobile Devices', 'All enrolled phones and tablets'),
    ('Windows Update - Pilot Ring', 'Early adopters for Windows quality updates'),
    ('Windows Update - Broad Ring', 'Default Windows Update ring'),
    ('Finance Department', 'Finance users'),
]


def _guid(rng):
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def _iso(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def _make_device(rng, now, hostname, user_name, upn, train_key, vulnerable):
    train = OS_TRAINS[train_key]
    os_name = train['operatingSystem']
    manufacturer, model = rng.choice(HARDWARE[os_name])
    enrolled = now - timedelta(days=rng.randint(90, 700))
    os_version = train['vulnerable'] if vulnerable else train['patched']
    return {
        'id': _guid(rng),
        'userId': _guid(rng),
        'deviceName': hostname,
        'managedDeviceOwnerType': 'company',
        'enrolledDateTime': _iso(enrolled),
        'lastSyncDateTime': _iso(now - timedelta(hours=rng.randint(1, 20), minutes=rng.randint(0, 59))),
        'operatingSystem': os_name,
        'complianceState': 'noncompliant' if vulnerable else 'compliant',
        'jailBroken': 'False' if os_name in ('iOS', 'Android') else 'Unknown',
        'managementAgent': 'mdm',
        'osVersion': os_version,
        'easActivated': True,
        'azureADRegistered': True,
        'deviceEnrollmentType': 'windowsAzureADJoin' if os_name == 'Windows' else 'appleBulkWithUser'
        if os_name in ('macOS', 'iOS') else 'androidEnterpriseFullyManaged',
        'emailAddress': upn,
        'azureADDeviceId': _guid(rng),
        'deviceRegistrationState': 'registered',
        'deviceCategoryDisplayName': 'Business Corp',
        'isSupervised': os_name in ('iOS', 'macOS'),
        'model': model,
        'manufacturer': manufacturer,
        'serialNumber': ''.join(rng.choice('ABCDEFGHJKLMNPQRSTUVWXYZ0123456789') for _ in range(10)),
        'userPrincipalName': upn,
        'userDisplayName': user_name,
        'managedDeviceName': f'{upn.split("@")[0]}_{os_name}_{enrolled.strftime("%m/%d/%Y")}',
        'isEncrypted': True,
        'partnerReportedThreatState': 'secured',
        'totalStorageSpaceInBytes': 511101108224,
        'freeStorageSpaceInBytes': rng.randint(80, 300) * 1024 ** 3,
        'deviceActionResults': [],
        # Simulator-only metadata, stripped from Graph responses
        '_train': train_key,
        '_persona': vulnerable,
    }


def build_fleet(filler_count):
    rng = random.Random(SEED)
    fake = Faker('fr_FR')
    fake.seed_instance(SEED)
    now = datetime.now(timezone.utc)

    devices = []
    for user in USERS:
        devices.append(_make_device(rng, now, user['hostname'], user['name'], user['email'],
                                    PERSONA_TRAIN[user['hostname']], vulnerable=True))

    filler_trains = ['win11_23h2'] * 9 + ['win10_22h2'] * 5 + ['macos_sonoma'] * 4 + ['ios_17'] * 4 + ['android_14'] * 2
    prefixes = {'Windows': 'BSNS-WIN', 'macOS': 'BSNS-MAC', 'iOS': 'BSNS-MOB', 'Android': 'BSNS-AND'}
    for i in range(filler_count):
        train_key = filler_trains[i % len(filler_trains)]
        first, last = fake.first_name(), fake.last_name()
        upn = f'{first}.{last}@{DOMAIN}'.lower().replace(' ', '')
        hostname = f'{prefixes[OS_TRAINS[train_key]["operatingSystem"]]}-{100 + i:03d}'
        devices.append(_make_device(rng, now, hostname, f'{first} {last}', upn, train_key, vulnerable=False))

    # Entra ID device objects (what group membership points to)
    entra_devices = []
    for d in devices:
        entra_devices.append({
            'id': _guid(rng),
            'deviceId': d['azureADDeviceId'],
            'displayName': d['deviceName'],
            'accountEnabled': True,
            'operatingSystem': d['operatingSystem'],
            'operatingSystemVersion': d['osVersion'],
            'trustType': 'AzureAd' if d['operatingSystem'] == 'Windows' else 'Workplace',
            'isManaged': True,
            'isCompliant': d['complianceState'] == 'compliant',
            'registrationDateTime': d['enrolledDateTime'],
            'approximateLastSignInDateTime': d['lastSyncDateTime'],
        })

    groups = []
    for g in REMEDIATION_GROUPS:
        groups.append({
            'id': _guid(rng), 'displayName': g['displayName'], 'description': g['description'],
            'groupTypes': [], 'securityEnabled': True, 'mailEnabled': False, 'mailNickname': g['displayName'],
            'membershipRule': None, 'createdDateTime': _iso(now - timedelta(days=30)),
            '_remediation': g['key'], '_policy': g['policy'], '_os': g['operatingSystem'],
        })
    for name, desc in OTHER_GROUPS:
        groups.append({
            'id': _guid(rng), 'displayName': name, 'description': desc,
            'groupTypes': [], 'securityEnabled': True, 'mailEnabled': False,
            'mailNickname': name.replace(' ', ''), 'membershipRule': None,
            'createdDateTime': _iso(now - timedelta(days=rng.randint(200, 900))),
        })

    return devices, entra_devices, groups
