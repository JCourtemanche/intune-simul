import os


class Config:
    DEBUG = os.environ.get('DEBUG', 'True').lower() == 'true'
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 8080))

    # Fake Entra ID app registration (client credentials flow)
    TENANT_ID = os.environ.get('SIM_TENANT_ID', '00000000-0000-0000-0000-000000000000')
    CLIENT_ID = os.environ.get('SIM_CLIENT_ID', '11111111-1111-1111-1111-111111111111')
    CLIENT_SECRET = os.environ.get('SIM_CLIENT_SECRET', 'change-me-intune-simulator-secret')
    TOKEN_LIFETIME = int(os.environ.get('TOKEN_LIFETIME', 3599))

    # Fleet sizing (the 6 Business Corp personas are always present)
    FILLER_DEVICES = int(os.environ.get('FILLER_DEVICES', 24))

    # Patch engine timing
    # Seconds from device check-in (syncDevice) to "up to date"
    PATCH_DURATION_SECONDS = int(os.environ.get('PATCH_DURATION_SECONDS', 150))
    # Without an explicit syncDevice, the device checks in on its own after this delay
    CHECKIN_FALLBACK_SECONDS = int(os.environ.get('CHECKIN_FALLBACK_SECONDS', 300))
    # Seconds for a syncDevice action to go from "pending" to "done"
    SYNC_ACTION_SECONDS = int(os.environ.get('SYNC_ACTION_SECONDS', 10))
