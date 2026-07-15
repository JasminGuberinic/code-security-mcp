"""Domain layer: the pure vocabulary of the problem.

Nothing in this package is allowed to import a framework, run a subprocess, or
touch the network. It only describes *what a security finding is* and *what a
security analyzer promises to do*. Everything concrete (detekt, SARIF, MCP)
lives in outer layers and depends inward on these definitions — never the
other way around.
"""
