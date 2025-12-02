#ifndef NT_VERSION_H
#define NT_VERSION_H

#define NT_STR2(str)    #str
#define NT_STR(str)     NT_STR2(str)

#define APPLICATION_NAME        "Nt Agent"
#define NT_REVDATE              "22 October 2025"
#define NT_VERSION_MAJOR        7
#define NT_VERSION_MINOR        4
#define NT_VERSION_PATCH        4
#define NT_VERSION_BUF_LEN      64
#ifndef NT_VERSION_REVISION
#       define NT_VERSION_REVISION      {NT_REVISION}
#endif
#ifdef _WINDOWS
#       ifndef NT_VERSION_RC_NUM
#               define NT_VERSION_RC_NUM        {NT_RC_NUM}
#       endif
#endif
#define NT_VERSION_RC   "rc1"
#define NT_VERSION              NT_STR(NT_VERSION_MAJOR) "." NT_STR(NT_VERSION_MINOR) "." \
                                NT_STR(NT_VERSION_PATCH) NT_VERSION_RC
#define NT_VERSION_SHORT        NT_STR(NT_VERSION_MAJOR) "." NT_STR(NT_VERSION_MINOR) "." \
                                NT_STR(NT_VERSION_PATCH)
#define NT_REVISION             NT_STR(NT_VERSION_REVISION)

#define NT_COMPONENT_VERSION(major, minor, patch) \
                                (((major) << 16) | ((minor) << 8) | (patch))
#define NT_COMPONENT_VERSION_WITHOUT_PATCH(ver)    ((ver) & ~0xFF)

#endif /* NT_VERSION_H */
