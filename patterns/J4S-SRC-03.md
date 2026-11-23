# J4S-SRC-03 — Untrusted input source signatures (`SOURCE_PATTERNS`, runbook §6)

**Area:** 2. Java source patterns (reachability of `java.util.Base64` decoding)  
**Source:** `../cve_2026_114938_java4shell_remediation_verification_runbook.md`  
**Index:** [SPEC.md](SPEC.md)

- **Surface:** captured argument expression + enclosing context (−15 / +5 lines)
- **Flavor:** Python, `re.IGNORECASE`
- **Severity on match:** MITIGATE (classifies as `DYNAMIC_UNTRUSTED`)

| Label | Pattern |
| :--- | :--- |
| `http_auth_header` | `\b(?:getHeader\|getHeaders\|Authorization\|Proxy-Authorization\|Basic)\b` |
| `http_request_input` | `\b(?:getParameter\|getInputStream\|getReader\|getBody\|ServerHttpRequest\|HttpServletRequest\|@RequestBody\|@RequestHeader\|@PathVariable)\b` |
| `jwt_saml_token` | `\b(?:jwt\|jws\|saml\|bearer\|id_token\|access_token)\b` |
| `file_or_stream_io` | `\b(?:Files\.read\|FileInputStream\|InputStream\|BufferedReader\|Scanner\|MultipartFile)\b` |
| `messaging_or_net` | `\b(?:ConsumerRecord\|Message\|SQS\|Kafka\|Socket\|URLConnection\|HttpClient\|WebClient)\b` |

(The `\|` above is a table escape; the real alternation character is `|`.)

- **Classification rules** (`classify_expression`):
  - Argument is a string literal `"(?:\\.|[^"\\])*"` **or** a constant identifier `[A-Z][A-Z0-9_]{2,}` **and** no source label matched → `CONSTANT`.
  - Any source label matched → `DYNAMIC_UNTRUSTED`.
  - Non-empty argument, no label → `DYNAMIC_INTERNAL`.
  - Empty → `UNKNOWN`.
