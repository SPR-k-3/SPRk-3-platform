# SPR{K}3 Rule Catalog

## Vulnerability Detection Rules

| Rule ID | Severity | CWE | Taint Bump | Description | Fix Hint |
|---------|----------|-----|------------|-------------|----------|
| torch_unsafe | CRITICAL | CWE-502 | +1 if tainted | Unsafe torch.load() allows arbitrary code execution | `torch.load(path, weights_only=True)` |
| pickle_unsafe | CRITICAL | CWE-502 | +1 if tainted | Pickle deserialization executes arbitrary code | Use JSON or MessagePack |
| subprocess_shell | CRITICAL | CWE-78 | +1 if tainted | Command injection via shell=True | `subprocess.run(["cmd", "arg"], check=True)` |
| aws_credentials | CRITICAL | CWE-798 | N/A | Hardcoded AWS credentials | Use IAM roles or env vars |
| private_key | CRITICAL | CWE-798 | N/A | Private key in code | Store in vault/secret manager |
| os_system | HIGH | CWE-78 | +1 if tainted | Command injection risk | `subprocess.run(["cmd"], check=True)` |
| os_popen | HIGH | CWE-78 | +1 if tainted | Command injection risk | `subprocess.Popen(["cmd"])` |
| eval_usage | HIGH | CWE-95 | +1 if tainted | Code injection via eval() | `ast.literal_eval()` |
| exec_usage | HIGH | CWE-95 | +1 if tainted | Code injection via exec() | Refactor to avoid |
| transformers_unsafe | HIGH | CWE-502 | +1 if unpinned | Remote code execution | Pin revision, verify trust |
| yaml_unsafe | HIGH | CWE-502 | +1 if tainted | YAML deserialization | `yaml.safe_load()` |
| sql_format | HIGH | CWE-89 | +1 if tainted | SQL injection | Use parameterized queries |
| sql_f_string | HIGH | CWE-89 | +1 if tainted | SQL injection via f-strings | Use placeholders |
| model_from_url | HIGH | CWE-494 | N/A | Unverified model download | Verify checksum/signature |
| tensorflow_load_unsafe | HIGH | CWE-502 | -1 if literal | Lambda layer execution | `custom_objects=None` |
| hardcoded_secret | HIGH | CWE-798 | N/A | Credentials in code | Use environment variables |
| ssl_verify_false | MEDIUM | CWE-295 | N/A | Disabled certificate verification | `verify=True` |
| md5_usage | MEDIUM | CWE-328 | N/A | Weak cryptography | Use SHA-256 |
| tempfile_mktemp | MEDIUM | CWE-377 | N/A | Race condition | Use `mkstemp()` |
| random_seed_fixed | LOW | CWE-338 | N/A | Fixed random seed | Remove in production |
| assert_used | LOW | CWE-617 | N/A | Assertions can be disabled | Use explicit checks |

## Taint Analysis

Sources that increase severity:
- `request`, `user`, `input`, `args`, `argv`
- `environ`, `getenv`, `POST`, `GET`, `params`
- `flask.request`, `django.request`

Literals that decrease severity:
- String/number literals only
- No variables or function calls
