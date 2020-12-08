''' Diagnostic Tests '''
import pytest
from yarals import helpers
from yarals.base import protocol
from yarals.base import errors as ce

# don't care about pylint(protected-access) warnings since these are just tests
# pylint: disable=W0212


@pytest.mark.asyncio
async def test_diagnostics(yara_server):
    ''' Ensure a diagnostic error message is provided when appropriate '''
    document = "rule OneDiagnostic { condition: $true }"
    result = await yara_server.provide_diagnostic(document)
    assert len(result) == 1
    diagnostic = result[0]
    assert isinstance(diagnostic, protocol.Diagnostic) is True
    assert diagnostic.severity == 1
    assert diagnostic.message == "undefined string \"$true\""
    assert diagnostic.range.start.line == 0
    assert diagnostic.range.end.line == 0

@pytest.mark.asyncio
async def test_diagnostics_no_results(yara_server):
    ''' Ensure no diagnostics are provided when rules are successfully compiled '''
    document = "rule NoDiagnostics { condition: true }"
    result = await yara_server.provide_diagnostic(document)
    assert result == []

@pytest.mark.asyncio
async def test_diagnostics_notify_user(uninstall_pkg, yara_server):
    ''' Ensure the diagnostics notify the user if yara-python is not installed '''
    expected_msg = "yara-python is not installed. Diagnostics and Compile commands are disabled"
    document = "rule NotifyUserDiagnostic { condition: $true }"
    await uninstall_pkg("yara-python")
    with pytest.raises(ce.NoDependencyFound) as excinfo:
        await yara_server.provide_diagnostic(document)
    assert expected_msg == str(excinfo.value)
