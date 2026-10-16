# Secure patterns available

What `secure_pattern` can currently answer. Call it with a short noun phrase
from the left column. Searching without a framework finds all of these;
filtering by framework narrows to that row only.

| Search for | Framework | Covers |
|---|---|---|
| `session cookie` | vertx | Secure, HttpOnly and SameSite on a session cookie (CWE-614) |
| `current user` | spring-webflux | Reading the authenticated principal in reactive code without blocking |
| `WebClient TLS` | spring-webflux | Configuring WebClient TLS without disabling verification |
| `SSLContext` | any | Choosing a safe protocol instead of the JVM default |
| `store a secret` | any | Keeping signing keys and secrets out of source |
| `random token` | any | Generating tokens with an OS-seeded source |
| `CORS` | ktor | CORS configuration that does not fall open |

Seven patterns, so a miss is common. An empty result means no vetted pattern
exists for that task — it does not mean the task is safe. Fall back to
`security_scan` or `review_diff` after writing the code, and apply ordinary
judgement in between.

Patterns are JVM-focused. For Python, C# and JS/TS, write the code and check it
with `review_diff`.
