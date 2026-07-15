"""Adapters: the concrete outer edge that fulfills the domain's ports.

This is the only layer allowed to know about the messy real world — running a
JVM subprocess, parsing SARIF, talking to a specific analyzer's CLI. If we ever
add a Python or Java analyzer, its adapter lives here too, each translating its
tool's raw output into the same domain `Finding` vocabulary.
"""
