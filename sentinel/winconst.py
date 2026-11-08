"""Named Windows API constants (so the code never carries bare hex flags)."""

# File attributes (winnt.h)
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000   # OneDrive "online-only": reading would download it
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003           # NTFS junction

# Drives and processes
DRIVE_FIXED = 3                                   # skips USB sticks, DVD and network drives
BELOW_NORMAL_PRIORITY_CLASS = 0x00004000

# PE section characteristics (IMAGE_SCN_*)
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000

# WinVerifyTrust (Authenticode)
WTD_REVOCATION_CHECK_NONE = 0x10
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000

# DPAPI
CRYPTPROTECT_UI_FORBIDDEN = 0x1

# User32
SPI_GETCLIENTAREAANIMATION = 0x1042
MB_ICONWARNING = 0x30
MB_TOPMOST = 0x40000

# Windows API codes used by the single-instance guard and the fatal-error box
ERROR_ALREADY_EXISTS = 183
SW_RESTORE = 9
MB_ICONERROR = 0x10
