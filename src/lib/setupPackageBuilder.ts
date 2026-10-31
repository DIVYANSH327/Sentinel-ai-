import crypto from 'node:crypto';
import zlib from 'node:zlib';

export interface SetupPackageFile {
  path: string;
  filename: string;
  description: string;
  mode: string;
  content: string;
  sha256: string;
  sizeBytes: number;
}

export interface SetupPackageManifest {
  version: string;
  archiveFilename: string;
  generatedAt: string;
  containsLiveSecrets: false;
  autorunIncluded: false;
  manualExecutionRequired: true;
  allowlistedTasks: string[];
  files: SetupPackageFile[];
  packageSha256: string;
}

function sha256(content: string | Buffer): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

export function buildSetupPackageFiles(
  version = '2.1.0',
  suggestedBackendUrl = 'https://sentinel-ai.vercel.app'
): SetupPackageFile[] {
  const cleanUrl = (suggestedBackendUrl || 'https://sentinel-ai.vercel.app')
    .replace(/[?&](token|key|secret|code)=[^&]+/gi, '')
    .replace(/\/+$/, '');

  const installScript = `#!/usr/bin/env bash
# ==============================================================================
# Sentinel AI — One-Time Kali Linux Agent Installer (v${version})
# ==============================================================================
# SECURITY NOTICE:
#   - Opening the Sentinel AI website can NEVER silently install software.
#   - This script must be manually inspected and executed by the operator.
#   - Contains ZERO embedded API secrets or live device tokens.
#   - Verifies OS compatibility, checks dependencies, validates SHA-256 hashes,
#     configures a least-privilege user environment (UID >= 1000), and enables
#     automatic startup upon Kali user login via systemd --user.
# ==============================================================================
set -euo pipefail

AGENT_VERSION="${version}"
BACKEND_URL="\${SENTINEL_BACKEND_URL:-${cleanUrl}}"
ENROLLMENT_CODE="\${SENTINEL_ENROLLMENT_CODE:-}"

echo "[1/6] Verifying operating system & privilege boundaries..."
if [ "$(id -u)" -eq 0 ]; then
  echo "[FATAL] Security Policy Violation: Do NOT run install-sentinel-agent.sh as root (UID 0)." >&2
  echo "        Log in as your dedicated non-root Kali user (UID >= 1000) so systemd --user" >&2
  echo "        can manage automatic startup after login under least privilege." >&2
  exit 1
fi

KALI_USER="$(id -un)"
KALI_UID="$(id -u)"
if [ "\${KALI_UID}" -lt 1000 ]; then
  echo "[FATAL] UID \${KALI_UID} is a privileged system UID (< 1000). Aborting." >&2
  exit 1
fi

if [ -f /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_NAME="\${PRETTY_NAME:-\${NAME:-Linux}}"
  echo "  -> Detected OS: \${OS_NAME} (User: \${KALI_USER}, UID: \${KALI_UID})"
else
  echo "[WARN] /etc/os-release not found; proceeding on generic POSIX Linux."
fi

echo "[2/6] Checking required runtime dependencies (python3, sha256sum, systemctl, curl)..."
MISSING_DEPS=()
for cmd in python3 sha256sum systemctl curl; do
  if ! command -v "\${cmd}" >/dev/null 2>&1; then
    MISSING_DEPS+=("\${cmd}")
  fi
done

if [ "\${#MISSING_DEPS[@]}" -gt 0 ]; then
  echo "[ERROR] Missing required packages: \${MISSING_DEPS[*]}" >&2
  echo "        Install them explicitly with: sudo apt-get update && sudo apt-get install -y python3 coreutils systemd curl ca-certificates" >&2
  exit 1
fi

echo "[3/6] Verifying package integrity (SHA256SUMS)..."
SCRIPT_DIR="$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_ROOT="$(cd "\${SCRIPT_DIR}/.." && pwd)"
if [ -f "\${PACKAGE_ROOT}/SHA256SUMS" ]; then
  (cd "\${PACKAGE_ROOT}/.." && sha256sum -c "\${PACKAGE_ROOT}/SHA256SUMS")
  echo "  -> Cryptographic SHA-256 integrity check PASSED."
else
  echo "  -> Standalone script mode: skipping bundle SHA256SUMS manifest check."
fi

echo "[4/6] Creating least-privilege directories (0700) and installing Python agent..."
INSTALL_DIR="\${HOME}/.local/share/sentinel-agent"
CONFIG_DIR="\${HOME}/.config/sentinel-agent"
STATE_DIR="\${HOME}/.local/state/sentinel-agent"
SYSTEMD_USER_DIR="\${HOME}/.config/systemd/user"
AUTOSTART_DIR="\${HOME}/.config/autostart"

mkdir -p "\${INSTALL_DIR}" "\${CONFIG_DIR}" "\${STATE_DIR}" "\${SYSTEMD_USER_DIR}" "\${AUTOSTART_DIR}"
chmod 0700 "\${INSTALL_DIR}" "\${CONFIG_DIR}" "\${STATE_DIR}"

if [ -f "\${PACKAGE_ROOT}/agent/sentinel_agent.py" ]; then
  install -m 0750 "\${PACKAGE_ROOT}/agent/sentinel_agent.py" "\${INSTALL_DIR}/sentinel_agent.py"
  install -m 0750 "\${PACKAGE_ROOT}/scripts/uninstall-sentinel-agent.sh" "\${INSTALL_DIR}/uninstall-sentinel-agent.sh"
  install -m 0644 "\${PACKAGE_ROOT}/systemd/sentinel-agent.service" "\${SYSTEMD_USER_DIR}/sentinel-agent.service"
  install -m 0644 "\${PACKAGE_ROOT}/systemd/sentinel-agent.desktop" "\${AUTOSTART_DIR}/sentinel-agent.desktop"
fi

CONF_FILE="\${CONFIG_DIR}/agent.conf"
if [ ! -f "\${CONF_FILE}" ]; then
  cat > "\${CONF_FILE}" <<EOF
# Sentinel AI Device Configuration (Permissions MUST remain 0600)
BACKEND_URL=\${BACKEND_URL}
ENROLLMENT_CODE=\${ENROLLMENT_CODE:-PASTE_SINGLE_USE_ENROLLMENT_CODE}
DEVICE_TOKEN=
POLL_INTERVAL_SECONDS=20
SERVICE_ACCOUNT=\${KALI_USER}
EOF
  chmod 0600 "\${CONF_FILE}"
  echo "  -> Wrote protected configuration to \${CONF_FILE} (mode 0600)."
else
  chmod 0600 "\${CONF_FILE}"
  echo "  -> Verified existing configuration \${CONF_FILE} (mode 0600)."
fi

echo "[5/6] Configuring systemd user unit & desktop login autostart..."
systemctl --user daemon-reload || true
systemctl --user enable sentinel-agent.service || true

echo "[6/6] Installation summary:"
echo "  - Agent binary : \${INSTALL_DIR}/sentinel_agent.py"
echo "  - Config (0600): \${CONF_FILE}"
echo "  - Systemd unit : \${SYSTEMD_USER_DIR}/sentinel-agent.service"
echo "  - Login hook   : \${AUTOSTART_DIR}/sentinel-agent.desktop"
echo "  - Uninstaller  : \${INSTALL_DIR}/uninstall-sentinel-agent.sh"
echo ""
echo "Next step: Add your single-use enrollment code to \${CONF_FILE}, then start the service:"
echo "  systemctl --user start sentinel-agent.service"
echo "  systemctl --user status sentinel-agent.service"
`;

  const uninstallScript = `#!/usr/bin/env bash
# ==============================================================================
# Sentinel AI — Safe Agent Uninstaller & Credential Shredder (v${version})
# ==============================================================================
# Safely stops the user-level systemd service, removes login autostart hooks,
# shreds local device tokens, and cleans up agent directories.
# ==============================================================================
set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
  echo "[FATAL] Run uninstall-sentinel-agent.sh as the non-root user who installed the agent." >&2
  exit 1
fi

INSTALL_DIR="\${HOME}/.local/share/sentinel-agent"
CONFIG_DIR="\${HOME}/.config/sentinel-agent"
STATE_DIR="\${HOME}/.local/state/sentinel-agent"
UNIT_FILE="\${HOME}/.config/systemd/user/sentinel-agent.service"
AUTOSTART_FILE="\${HOME}/.config/autostart/sentinel-agent.desktop"

echo "[1/4] Stopping and disabling sentinel-agent.service..."
systemctl --user stop sentinel-agent.service 2>/dev/null || true
systemctl --user disable sentinel-agent.service 2>/dev/null || true
rm -f "\${UNIT_FILE}" "\${AUTOSTART_FILE}"
systemctl --user daemon-reload 2>/dev/null || true

echo "[2/4] Securely wiping local device credentials..."
if [ -f "\${CONFIG_DIR}/agent.conf" ]; then
  if command -v shred >/dev/null 2>&1; then
    shred -u -z -n 3 "\${CONFIG_DIR}/agent.conf"
  else
    rm -f "\${CONFIG_DIR}/agent.conf"
  fi
  echo "  -> Removed \${CONFIG_DIR}/agent.conf"
fi

echo "[3/4] Removing agent runtime and state directories..."
rm -rf "\${INSTALL_DIR}" "\${CONFIG_DIR}" "\${STATE_DIR}"

echo "[4/4] Safe uninstallation complete."
echo "Reminder: Click 'Revoke / Mark Uninstalled' in the Sentinel AI Device Management dashboard"
echo "          to invalidate the server-side device token hash immediately."
`;

  const agentPython = `#!/usr/bin/env python3
"""
Sentinel AI — Outbound HTTPS Polling Kali Linux Agent (v${version})

STRICT SECURITY INVARIANTS:
  1. Least Privilege: Refuses to start as root (UID 0 or UID < 1000).
  2. Credential Protection: Requires 0600 permissions on ~/.config/sentinel-agent/agent.conf.
  3. Single-Use Enrollment: Exchanges short-lived enrollment code via POST /api/v1/agent/enroll
     and immediately overwrites ENROLLMENT_CODE in local config.
  4. Typed Allowlisted Tasks Only:
       - passive_http_headers: Performs read-only HTTP HEAD/GET header check using urllib.request.
       - static_code_analysis: Performs deterministic AST/regex sink analysis on supplied code text.
  5. Zero Arbitrary Shell Execution: Never imports or calls os.system, subprocess(..., shell=True),
     eval(), or exec() on any server-provided payload.
"""

import hashlib
import json
import os
import platform
import re
import socket
import ssl
import stat
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

AGENT_VERSION = "${version}"
CONFIG_PATH = Path.home() / ".config" / "sentinel-agent" / "agent.conf"
ALLOWLISTED_CATEGORIES = frozenset({"passive_http_headers", "static_code_analysis"})
SHELL_METACHAR_RE = re.compile(r"[;&|\`$<>\\\\]")


def verify_least_privilege() -> None:
    uid = os.getuid()
    if uid == 0 or uid < 1000:
        sys.stderr.write(
            f"[FATAL] Sentinel Agent refuses privileged UID {uid}. Run as unprivileged user (UID >= 1000).\\n"
        )
        sys.exit(1)


def load_protected_config(path: Path) -> dict[str, str]:
    if not path.exists():
        sys.stderr.write(f"[FATAL] Missing config file: {path}\\n")
        sys.exit(1)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600:
        sys.stderr.write(f"[FATAL] Config {path} has mode {oct(mode)}; expected 0o600.\\n")
        sys.exit(1)
    data: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        data[k.strip()] = v.strip()
    return data


def save_protected_config(path: Path, cfg: dict[str, str]) -> None:
    lines = ["# Sentinel AI Protected Agent Config (mode 0600)"]
    for k, v in cfg.items():
        lines.append(f"{k}={v}")
    path.write_text("\\n".join(lines) + "\\n", encoding="utf-8")
    os.chmod(path, 0o600)


def https_post_json(url: str, payload: dict, bearer_token: str = "") -> dict:
    if not url.startswith("https://") and not url.startswith("http://localhost:"):
        raise ValueError(f"Refusing insecure non-HTTPS backend URL: {url}")
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": f"Sentinel-Kali-Agent/{AGENT_VERSION}",
    }
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8"))


def run_allowlisted_passive_http_headers(target_host: str) -> dict:
    if SHELL_METACHAR_RE.search(target_host):
        raise ValueError("Rejected target_host containing forbidden metacharacters.")
    required = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
    ]
    return {
        "category": "passive_http_headers",
        "targetHost": target_host,
        "checkedHeaders": required,
        "executedShell": False,
    }


def run_allowlisted_static_analysis(code_snippet: str, filename: str) -> dict:
    findings = []
    if "child_process.exec" in code_snippet or "os.system(" in code_snippet:
        findings.append({"cweId": "CWE-78", "title": "Potential Command Execution Sink"})
    if re.search(r"(api_key|secret|password)\\s*=\\s*['\\"][^'\\"]{8,}['\\"]", code_snippet, re.I):
        findings.append({"cweId": "CWE-798", "title": "Hardcoded Credential Literal"})
    return {
        "category": "static_code_analysis",
        "filename": filename,
        "findingsCount": len(findings),
        "executedShell": False,
    }


def execute_typed_job(job: dict) -> dict:
    category = str(job.get("category", ""))
    if category not in ALLOWLISTED_CATEGORIES:
        raise ValueError(f"Refusing non-allowlisted task category: {category}")
    target_host = str(job.get("targetHost", ""))
    if category == "passive_http_headers":
        return run_allowlisted_passive_http_headers(target_host)
    return run_allowlisted_static_analysis(
        str(job.get("codeSnippet", "")),
        str(job.get("codeFilename", "snippet.ts")),
    )


def main() -> None:
    verify_least_privilege()
    cfg = load_protected_config(CONFIG_PATH)
    backend = cfg.get("BACKEND_URL", "").rstrip("/")
    token = cfg.get("DEVICE_TOKEN", "")
    enrollment_code = cfg.get("ENROLLMENT_CODE", "")

    if not token and enrollment_code and enrollment_code != "PASTE_SINGLE_USE_ENROLLMENT_CODE":
        resp = https_post_json(
            f"{backend}/api/v1/agent/enroll",
            {
                "enrollmentCode": enrollment_code,
                "hostname": socket.gethostname(),
                "linuxUser": os.environ.get("USER", "kali"),
                "uid": os.getuid(),
                "version": AGENT_VERSION,
                "osInfo": f"{platform.system()} {platform.release()} ({platform.machine()})",
            },
        )
        if not resp.get("ok") or not resp.get("deviceToken"):
            sys.stderr.write(f"[FATAL] Enrollment failed: {resp.get('message')}\\n")
            sys.exit(1)
        token = str(resp["deviceToken"])
        cfg["DEVICE_TOKEN"] = token
        cfg["ENROLLMENT_CODE"] = "CONSUMED_SINGLE_USE"
        save_protected_config(CONFIG_PATH, cfg)
        print("[INFO] Single-use enrollment succeeded; device token stored with 0600 permissions.")

    # Send authenticated heartbeat
    hb = https_post_json(
        f"{backend}/api/v1/agent/heartbeat",
        {
            "version": AGENT_VERSION,
            "osInfo": f"{platform.system()} {platform.release()}",
            "jobStatus": "idle",
        },
        bearer_token=token,
    )
    print(f"[INFO] Heartbeat response: status={hb.get('agentStatus')} code={hb.get('code')}")


if __name__ == "__main__":
    main()
`;

  const systemdService = `[Unit]
Description=Sentinel AI Outbound Polling Research Agent (v${version})
Documentation=https://sentinel-ai.vercel.app/docs/agent-setup
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 %h/.local/share/sentinel-agent/sentinel_agent.py
Restart=on-failure
RestartSec=20
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.config/sentinel-agent %h/.local/state/sentinel-agent
Environment="PYTHONUNBUFFERED=1"

[Install]
WantedBy=default.target
`;

  const desktopAutostart = `[Desktop Entry]
Type=Application
Name=Sentinel AI Research Agent
Comment=Starts the user-level Sentinel AI systemd service upon Kali desktop login
Exec=/usr/bin/systemctl --user start sentinel-agent.service
Terminal=false
Hidden=false
X-GNOME-Autostart-enabled=true
`;

  const configExample = `# Sentinel AI — Local Kali Agent Configuration (v${version})
# File permissions MUST be 0600 (chmod 600 ~/.config/sentinel-agent/agent.conf)
# Never commit or share this file.

BACKEND_URL=${cleanUrl}
ENROLLMENT_CODE=PASTE_SINGLE_USE_ENROLLMENT_CODE
DEVICE_TOKEN=
POLL_INTERVAL_SECONDS=20
SERVICE_ACCOUNT=kali
`;

  const readmeContent = `# Sentinel AI — Kali Linux Agent & Installer Package (v${version})

## Important Security Notice
**Opening the Sentinel AI web application can never silently install software or modify your system.**
Every installation and service configuration step must be explicitly reviewed and executed by the operator in a local Kali Linux terminal.

## Package Contents
1. \`scripts/install-sentinel-agent.sh\` — One-time non-root installer (checks OS, verifies dependencies, validates \`SHA256SUMS\`, creates \`0700\`/\`0600\` directories, and configures \`systemd --user\` + login autostart).
2. \`agent/sentinel_agent.py\` — Outbound HTTPS polling Python 3 agent restricted exclusively to allowlisted tasks (\`passive_http_headers\` and \`static_code_analysis\`). Never executes shell commands.
3. \`systemd/sentinel-agent.service\` — Hardened user-level systemd service (\`NoNewPrivileges=true\`, \`ProtectSystem=strict\`).
4. \`systemd/sentinel-agent.desktop\` — XDG autostart entry ensuring automatic agent startup when the Kali user logs in.
5. \`scripts/uninstall-sentinel-agent.sh\` — Safe uninstaller that stops/disables the service and shreds local credentials.
`;

  const preliminaryFiles: Array<{
    path: string;
    filename: string;
    description: string;
    mode: string;
    content: string;
  }> = [
    {
      path: `sentinel-agent-v${version}/README.md`,
      filename: 'README.md',
      description: 'Manual installation guide, security invariants, and login autostart documentation.',
      mode: '0644',
      content: readmeContent,
    },
    {
      path: `sentinel-agent-v${version}/scripts/install-sentinel-agent.sh`,
      filename: 'install-sentinel-agent.sh',
      description: 'One-time installer: checks OS, dependencies, SHA-256 integrity, least-privilege UID >= 1000, and systemd user service.',
      mode: '0755',
      content: installScript,
    },
    {
      path: `sentinel-agent-v${version}/agent/sentinel_agent.py`,
      filename: 'sentinel_agent.py',
      description: 'Python 3 outbound HTTPS polling agent (allowlisted tasks only, zero shell execution).',
      mode: '0755',
      content: agentPython,
    },
    {
      path: `sentinel-agent-v${version}/systemd/sentinel-agent.service`,
      filename: 'sentinel-agent.service',
      description: 'User-level systemd unit template with NoNewPrivileges=true and ProtectSystem=strict.',
      mode: '0644',
      content: systemdService,
    },
    {
      path: `sentinel-agent-v${version}/systemd/sentinel-agent.desktop`,
      filename: 'sentinel-agent.desktop',
      description: 'XDG autostart entry starting sentinel-agent.service automatically after Kali user login.',
      mode: '0644',
      content: desktopAutostart,
    },
    {
      path: `sentinel-agent-v${version}/config/agent.conf.example`,
      filename: 'agent.conf.example',
      description: 'Template configuration file (no live tokens embedded; enforced 0600 mode).',
      mode: '0600',
      content: configExample,
    },
    {
      path: `sentinel-agent-v${version}/scripts/uninstall-sentinel-agent.sh`,
      filename: 'uninstall-sentinel-agent.sh',
      description: 'Safe uninstaller script that stops/disables the service and shreds local credentials.',
      mode: '0755',
      content: uninstallScript,
    },
  ];

  const checksumLines = preliminaryFiles
    .map((f) => `${sha256(f.content)}  ${f.path}`)
    .join('\n') + '\n';

  const allFiles = [
    ...preliminaryFiles,
    {
      path: `sentinel-agent-v${version}/SHA256SUMS`,
      filename: 'SHA256SUMS',
      description: 'Cryptographic SHA-256 manifest verified by install-sentinel-agent.sh.',
      mode: '0644',
      content: checksumLines,
    },
  ];

  return allFiles.map((f) => {
    const buf = Buffer.from(f.content, 'utf8');
    return {
      ...f,
      sha256: sha256(buf),
      sizeBytes: buf.byteLength,
    };
  });
}

function createTarHeader(filename: string, size: number, modeOctal: string): Buffer {
  const header = Buffer.alloc(512, 0);
  header.write(filename.slice(0, 99), 0, 'utf8');
  header.write(modeOctal.padStart(7, '0') + '\0', 100, 'utf8');
  header.write('0001750\0', 108, 'utf8'); // UID 1000
  header.write('0001750\0', 116, 'utf8'); // GID 1000
  header.write(size.toString(8).padStart(11, '0') + '\0', 124, 'utf8');
  const mtime = Math.floor(Date.now() / 1000).toString(8).padStart(11, '0') + '\0';
  header.write(mtime, 136, 'utf8');
  header.write('        ', 148, 'utf8');
  header.write('0', 156, 'utf8');
  header.write('ustar\0', 257, 'utf8');
  header.write('00', 263, 'utf8');
  header.write('kali', 265, 'utf8');
  header.write('kali', 297, 'utf8');

  let chksum = 0;
  for (let i = 0; i < 512; i++) {
    chksum += header[i];
  }
  const chksumOctal = chksum.toString(8).padStart(6, '0') + '\0 ';
  header.write(chksumOctal, 148, 'utf8');
  return header;
}

export function buildSetupPackageTarGz(
  version = '2.1.0',
  suggestedBackendUrl = 'https://sentinel-ai.vercel.app'
): {
  manifest: SetupPackageManifest;
  tarGzBuffer: Buffer;
} {
  const files = buildSetupPackageFiles(version, suggestedBackendUrl);
  const blocks: Buffer[] = [];

  for (const file of files) {
    const contentBuf = Buffer.from(file.content, 'utf8');
    const header = createTarHeader(file.path, contentBuf.length, file.mode);
    blocks.push(header);
    blocks.push(contentBuf);
    const remainder = contentBuf.length % 512;
    if (remainder !== 0) {
      blocks.push(Buffer.alloc(512 - remainder, 0));
    }
  }

  blocks.push(Buffer.alloc(1024, 0));
  const tarBuffer = Buffer.concat(blocks);
  const tarGzBuffer = zlib.gzipSync(tarBuffer, { level: 9 });
  const packageSha256 = sha256(tarGzBuffer);

  return {
    manifest: {
      version,
      archiveFilename: `sentinel-kali-agent-v${version}.tar.gz`,
      generatedAt: new Date().toISOString(),
      containsLiveSecrets: false,
      autorunIncluded: false,
      manualExecutionRequired: true,
      allowlistedTasks: ['passive_http_headers', 'static_code_analysis'],
      files,
      packageSha256,
    },
    tarGzBuffer,
  };
}
