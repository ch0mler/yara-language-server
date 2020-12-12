import "cuckoo"
import "pe"

rule ModuleCompletionExample
{
    meta:
        description = "Module Completion Example"
        author = "Test"
        reference = "https://infosec-intern.github.io"
    condition:
        cuckoo
}
rule VersionInfoCompletionExample
{
    meta:
        description = "Module Completion Example for pe.version_info"
        author = "Test"
    condition:
        pe.vers
}
rule IsDLLCompletionExample
{
    meta:
        description = "Module Completion Example for pe.is_dll()"
        author = "Test"
    condition:
        pe.is_dll
}