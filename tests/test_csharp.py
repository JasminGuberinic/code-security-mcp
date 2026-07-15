"""Tests for the C# (Roslyn) analyzer wiring — no .NET SDK required."""

from pathlib import Path

from code_security_mcp.adapters.roslyn_analyzer import (
    CSharpAnalyzer,
    RoslynConfig,
    _is_compiler_diagnostic,
)


def test_compiler_diagnostics_are_recognized():
    # Compiler diagnostics (CS####) are build noise, not security findings.
    assert _is_compiler_diagnostic("CS5001") is True
    # Analyzer security rules (CA####) must be kept.
    assert _is_compiler_diagnostic("CA5351") is False


def _config_with_sdk(tmp_path, **overrides) -> RoslynConfig:
    """A RoslynConfig whose `dotnet` executable exists (for supports()/env tests)."""
    sdk = tmp_path / "sdk"
    sdk.mkdir()
    (sdk / "dotnet").write_text("")  # a fake dotnet binary that exists
    base = dict(dotnet_root=sdk)
    base.update(overrides)
    return RoslynConfig(**base)


def test_unsupported_when_sdk_missing(tmp_path):
    config = RoslynConfig(dotnet_root=tmp_path / "no-sdk")
    (tmp_path / "app.csproj").write_text("<Project/>")
    assert CSharpAnalyzer(config).supports(tmp_path) is False


def test_prefers_solution_over_project(tmp_path):
    (tmp_path / "app.csproj").write_text("<Project/>")
    (tmp_path / "app.sln").write_text("")
    analyzer = CSharpAnalyzer(_config_with_sdk(tmp_path))

    resolved = analyzer._resolve_project(tmp_path)

    assert resolved is not None and resolved.suffix == ".sln"
    assert analyzer.supports(tmp_path) is True


def test_loose_cs_file_is_not_a_project(tmp_path):
    (tmp_path / "Program.cs").write_text("class C {}")
    analyzer = CSharpAnalyzer(_config_with_sdk(tmp_path))
    # A bare .cs file is not buildable on its own → unsupported.
    assert analyzer.supports(tmp_path) is False


def test_build_command_enables_security_only_and_sarif(tmp_path):
    analyzer = CSharpAnalyzer(_config_with_sdk(tmp_path))
    project = tmp_path / "app.csproj"

    command = analyzer._build_command(project, tmp_path / "out.sarif")

    assert command[1] == "build"
    assert "-p:AnalysisMode=None" in command
    assert "-p:AnalysisModeSecurity=All" in command
    assert any(arg.startswith("-p:ErrorLog=") and "version=2.1" in arg for arg in command)


def test_subprocess_env_is_isolated(tmp_path):
    config = _config_with_sdk(
        tmp_path, nuget_packages=tmp_path / "nuget", cli_home=tmp_path / "home"
    )
    env = CSharpAnalyzer(config)._subprocess_env()

    assert env["DOTNET_ROOT"] == str(config.dotnet_root)
    assert env["DOTNET_CLI_TELEMETRY_OPTOUT"] == "1"
    assert env["NUGET_PACKAGES"] == str(tmp_path / "nuget")
    assert env["DOTNET_CLI_HOME"] == str(tmp_path / "home")
