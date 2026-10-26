# Security

This project distributes generic installation and same-server recovery code.
It does not contain real node credentials, TLS keys, WARP registrations,
subscription links, backups or browser sessions.

Backup archives and generated configuration contain secrets and are not encrypted.
Do not attach them to public issues, pull requests or logs. Use GitHub private
vulnerability reporting when available; otherwise report only a high-level
description and a synthetic reproduction without private files or addresses.

Use this reference implementation only on a supported server you administer.
Read the scripts and service terms before running with root privileges. Core
releases are pinned and checksummed. Validate official artifacts and templates
when changing the pin.

Archive hashes detect corruption, not the authenticity of an untrusted backup.
Restore only files whose origin you trust. Same-machine configuration recovery
cannot replace a complete operating-system backup.

Generated secrets must never be committed, even to a private mirror. If a secret
is exposed, remove public access and rotate it; deleting a file does not remove
its old contents from Git history.
