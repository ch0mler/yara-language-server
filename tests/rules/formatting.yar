import "pe"

// open curly brace should be on next line
rule Formatting : test {
    meta:
        author = "test"
        reference = "github.com"
    // all variables should be under strings section
    strings: $a = "test"
        $b = { 40 41 42 43 }
        $c = /[a-fA-F0-0]{32}/
    condition:
        // new "and" conditions should be on next line
        uint16(0) == 0x5A4D and
        ($a or $b or $c) and for any i in (0..pe.number_of_signatures - 1) : (
            pe.signatures[i].issuer contains "Microsoft"
        )
}