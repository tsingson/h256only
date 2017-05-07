`h256only` command-line tool
=======================

This is a simple tool to sign, verify and show things that appear like JSON Web
Tokens from the command line.

The following will create and sign a token:

     bin/h256only -key test/sample_key -sign {\"foo\":\"bar\"}

To simply display a token, use:

    h256only -show $(echo $JWT)
