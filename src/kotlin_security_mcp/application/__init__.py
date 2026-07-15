"""Application layer: use cases that orchestrate the domain.

A use case is a single, named thing the system can *do* ("scan this code").
It depends only on domain ports, never on a concrete analyzer. That is what
lets us test it with a fake and run it in production with detekt, unchanged.
"""
