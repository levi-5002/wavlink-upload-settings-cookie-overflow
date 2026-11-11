# WAVLINK `upload_settings.cgi` Cookie stack overflow

- **Published:** 2026-11-11 (UTC+08:00)
- **Researcher:** [levi-5002](https://github.com/levi-5002)
- **Component:** `/cgi-bin/upload_settings.cgi`
- **Weakness:** CWE-121, stack-based buffer overflow
- **CVE status:** No CVE ID assigned at publication

## Affected samples

| Product | Tested firmware | Firmware package SHA-256 |
| --- | --- | --- |
| WL-WN570HA1B | M_V260622 | `0557d925a90594e4dc1e0c41988d4b4306bca4eb064ea78464375f4d61ee0043` |
| WL-WN570HA2 | M_V260622 | `927934253ef363a18601a7fe08fc652644f46ba2ac5d0707b154a08ce7e093ef` |
| WL-WN575A3-B | A3_V260724 | `e0433db404bee333d9a4296153b4fb4cee2b5b0e15dad96184a537fbf70d18b0` |

The extracted `upload_settings.cgi` executable has MD5 `db1f9adbb473df9e696ba83da3c822d9` in all three tested packages. Other products and firmware versions have not been verified.

## Finding

The CGI reads the `token=` value from `HTTP_COOKIE` and copies it into a fixed-size stack buffer with `strcpy` without adequate length validation. The vulnerable path is reached before successful session authentication. A client that can access the device's web management interface can supply an oversized Cookie to corrupt the CGI process stack.

The demonstrated outcome is a CGI process crash with overwritten control-flow registers in the emulated path. This research does not establish arbitrary code execution, persistent device-wide denial of service, or exploitation on physical hardware.

## Evidence

The original MIPS CGI was tested under QEMU behind a native lighttpd HTTP boundary. A 512-byte Cookie containing `token=` reached the CGI and produced HTTP 500. Direct QEMU execution terminated with SIGSEGV (return code `-11`). GDB recorded `pc: 0x41414141` and `ra: 0x41414141` after the oversized input.

- [Isolated reproduction result](evidence/upload_settings_repro.json)
- [GDB crash excerpt](evidence/upload_settings_gdb.txt)

These observations show a reachable stack overwrite in the tested emulation environment. The firmware images and CGI binary are not redistributed here.

## Relationship to other CVEs

- [CVE-2026-18607](https://www.cve.org/CVERecord?id=CVE-2026-18607) describes an `HTTP_COOKIE` overflow in a different executable, `upload.cgi`. Whether both Cookie handlers share one independently fixable source-level defect remains for CNA review.
- [CVE-2026-18587](https://www.cve.org/CVERecord?id=CVE-2026-18587) mentions `upload_settings.cgi` in another WAVLINK product but describes configuration-import command injection, a different mechanism.
- [CVE-2025-55847](https://www.cve.org/CVERecord?id=CVE-2025-55847) and [CVE-2026-109109](https://www.cve.org/CVERecord?id=CVE-2026-109109) concern Cookie overflows in `ExportAllSettings.cgi`. Shared vulnerable source code has not been established.

This finding should be checked against existing records before a separate CVE ID is assigned. Different CGI filenames alone do not establish independent fixability.

## Mitigation and coordination

Restrict access to the web management interface until a vendor fix is available. The CGI should validate Cookie length and bound the copy to the destination buffer. No fixed firmware version has been confirmed by this research.

The researcher reports emailing WAVLINK privately about this finding before publication. No vendor reply or delivery confirmation had been received at publication. This advisory was published on 2026-11-11; a CVE ID had not been assigned.
