Function New-Password {
    <#
    .SYNOPSIS
    Generates a random password.
    .DESCRIPTION
    The New-Password cmdlet generates a string of random characters, generally used to create a password. You can specify the pools of characters to generate from, supply your own, or use a template.
    .PARAMETER Length
    Specifies the number of characters for the generated password.
    .PARAMETER Mode
    Specifies whether to generate the password evenly between the different alphabets as the password is generated, or to generate the password completely at random (characters from larger alphabets are more likely to end up getting picked). To illustrate the difference better, call the cmdlet with the -Verbose parameter.
    
    Valid values are:

        EqualMode: Distributes the password amongst the selected alphabets equally. This is the default.

        TotalMode: Selects from the entire alphabet space (larger alphabets will take up a bigger portion of the password). 
    
    .PARAMETER UseLowerCase
    Specifies whether or not to use lowercase letters in the password pool.
    .PARAMETER UseUpperCase
    Specifies whether or not to use uppercase letters in the password pool.
    .PARAMETER UseDecimalNumbers
    Specifies whether or not to use decimal numbers in the password pool.
    .PARAMETER UseSymbols
    Specifies whether or not to use symbols in the password pool.
    .PARAMETER AvoidSimilar
    Specifies whether or not to avoid characters that looke alike, and can be hard to discern from one another.
    .PARAMETER AvoidProgramming
    Specifies whether or not to avoid characters that are used in programming languages.
    .PARAMETER PhoneticOutput
    Prints the password as a series of words from the phonetic alphabet.
    .PARAMETER CustomPattern
    Specifies a custom set of characters that should be used as an alphabet.
    .PARAMETER Template
    Generate password based on a template string. The following placeholders are accepted:

        l: Letters
        v: Vowels
        c: Consonants
        !: Symbols
        d: Decimal numbers
        h: Hexadecimal numbers
        o: Octal numbers
        b: Binary numbers
        a: Letters and decimal numbers
        *: Letters, decimal numbers and symbols
        .: Lowercase modifier
        :: Uppercase modifier
        -: Used for escaping any of the above placeholders

    See examples for more information.
    .EXAMPLE
    Generate a random password consisting of 15 characters, selected from lowercase letters, uppercase letters and numbers.

    New-Password
    .EXAMPLE
    Generate a 20-digit random binary number.

    "01" | New-Password -Length 20

    or

    New-Password -Template 'bbbbbbbbbbbbbbbbbbbb'
    .EXAMPLE
    Generate a password that includes symbols, numbers and lowercase letters.

    New-Password -UseSymbols -UseUpperCase:$false
    .EXAMPLE
    Generate a password where the characters are evenly distributed amongst all the alphabets.

    New-Password -UseSymbols -Mode EqualMode
    .EXAMPLE
    Generate a password and print it with the phonetic alphabet to make it easier to remember / communicate.

    New-Password -PhoneticOutput
    .EXAMPLE
    Generate a typical Azure-type password

    New-Password -Template ':c.v.c.v.cdd'
    .EXAMPLE
    Generate a password where some of the characters are predefined. This will generate a password with three letters, an underscore, a colon, a symbol, another colon, another underscore, and finally three more letters.

    New-Password -Template 'lll_-:!-:_lll'
    .INPUTS
    System.String
    .OUTPUTS
    System.String
    #>
    [CmdletBinding(DefaultParameterSetName='StandardSet')]
    Param (
        [Parameter(ParameterSetName='StandardSet')]
        [Parameter(ParameterSetName='CustomPatternSet')]
        [Int]
        $Length = 15,

        # Use -Verbose to better understand the difference between these two
        [Parameter(ParameterSetName='StandardSet')]
        [ValidateSet ("TotalMode", "EqualMode")]
        [String]
        $Mode='EqualMode',

        [Parameter(ParameterSetName='TemplateSet', Mandatory=$true)]
        [String]
        $Template = '',

        [Parameter(ParameterSetName='StandardSet')]
        [Switch]
        $UseLowerCase=$true,

        [Parameter(ParameterSetName='StandardSet')]
        [Switch]
        $UseUpperCase=$true,
        
        [Parameter(ParameterSetName='StandardSet')]
        [Switch]
        $UseDecimalNumbers=$true,

        [Parameter(ParameterSetName='StandardSet')]
        [Switch]
        $UseSymbols,

        [Parameter(ParameterSetName='TemplateSet')]
        [Parameter(ParameterSetName='StandardSet')]
        [Switch]
        $AvoidSimilar,

        [Parameter(ParameterSetName='TemplateSet')]
        [Parameter(ParameterSetName='StandardSet')]
        [Switch]
        $AvoidProgramming,

        [Parameter(ParameterSetName='StandardSet')]
        [Parameter(ParameterSetName='TemplateSet')]
        [Parameter(ParameterSetName='CustomPatternSet')]
        [Switch]
        $PhoneticOutput,

        [Parameter(ValueFromPipeline=$true, ParameterSetName='CustomPatternSet', Mandatory=$true)]
        [String]
        $CustomPattern
    )

#region Declarations
    $SimilarCharacters = @( '1', '|', 'I', 'l', '!', 'O', '0', '`', '´', "'", ';', ':' )
    $ProgrammingCharacters = @( '$', "'", '"', '&', ',', '?', '@', '#', '<', '>', '(', ')', '{', '}', '[', ']', '/', '\' )

    # Statistical counters
    $LCC = 0
    $UCC = 0
    $NC = 0
    $SC = 0

    # TODO: Replace these with some sort of auto-generated list of letters, based on i18n, etc
    $LowerCaseAlphabet = @( "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z" )
    $UpperCaseAlphabet = @( "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z" )

    $Vowels = @( 'a', 'e', 'i', 'o', 'u', 'y' )
    $Consonants = @( "b", "c", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p", "q", "r", "s", "t", "v", "w", "x", "z" )

    $DecimalAlphabet = @( "0", "1", "2", "3", "4", "5", "6", "7", "8", "9" )
    $HexaDecimalAlphabet = @( '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' )
    $OctalAlphabet = @( '0', '1', '2', '3', '4', '5', '6', '7' )
    $BinaryAlphabet = @( '0', '1' )

    $SymbolAlphabet = @( "§", "|", "!", "`"", "@", "#", "£", "¤", "$", "%", "€", "&", "/", "{", "(", "[", ")", "]", "=", "}", "\", "``", "´", "¨", "^", "~", "'", "*", "<", ">", ",", ";", ".", ":", "-", "_" )

    $TotalAlphabet = @()
#endregion

    Function ConvertTo-Phonetic ([String] $Character) {
        $PhoneticTable = @{ 'a' = 'alfa'; 'b' = 'bravo'; 'c' = 'charlie'; 'd' = 'delta'; 'e' = 'echo'; 'f' = 'foxtrot'; 'g' = 'golf'; 'h' = 'hotel'; 'i' = 'india'; 'j' = 'juliett'; 'k' = 'kilo'; 'l' = 'lima'; 'm' = 'mike'; 'n' = 'november'; 'o' = 'oscar'; 'p' = 'papa'; 'q' = 'quebec'; 'r' = 'romeo'; 's' = 'sierra'; 't' = 'tango'; 'u' = 'uniform'; 'v' = 'victor'; 'w' = 'whiskey'; 'x' = 'x-ray'; 'y' = 'yankee'; 'z' = 'zulu' }
    
        if ($LowerCaseAlphabet.Contains($Character.ToLower())) {
            $retval = $null

            if ($Character.ToLower() -ceq $Character) {
                $retval = $PhoneticTable[$Character]
            } else {
                $retval = ($PhoneticTable[$Character.ToLower()]).ToUpper()
            }
            return $retval
        } else {
            return $Character
        }
    }

    Function Approve ([String] $Character) {
        if (!($AvoidSimilar -or $AvoidProgramming)) {
            return $true
        } else {
            if ($AvoidSimilar -and $SimilarCharacters.Contains($Character)) {
                return $false
            }
            if ($AvoidProgramming -and $ProgrammingCharacters.Contains($Character)) {
                return $false
            }
        }
        return $true
    }

    Function Count ([String] $Character) {
        if ($LowerCaseAlphabet.Contains($Character)) {
            $SV = Get-Variable -Name LCC -Scope 1
            $SV.Value = $SV.Value + 1
            return
        }
        if ($UpperCaseAlphabet.Contains($Character)) {
            $SV = Get-Variable -Name UCC -Scope 1
            $SV.Value = $SV.Value + 1        
            return
        }
        if ($DecimalAlphabet.Contains($Character)) {
            $SV = Get-Variable -Name NC -Scope 1
            $SV.Value = $SV.Value + 1
            return
        }
        if ($SymbolAlphabet.Contains($Character)) {
            $SV = Get-Variable -Name SC -Scope 1
            $SV.Value = $SV.Value + 1
            return
        }
        return
    }

    Function Get-Case ([String] $Character) {
        if ($Character.ToLower() -ceq $Character) {
            return $true
        } else {
            return $false
        }
    }

    Function Get-Pool ([String] $CharacterClass) {
        switch ($CharacterClass) {
            'l' { return $LowerCaseAlphabet; break }
            'v' { return $Vowels; break }
            'c' { return $Consonants; break }
            'h' { return $HexaDecimalAlphabet; break }
            'a' { return $LowerCaseAlphabet + $DecimalAlphabet; break }
            '*' { return $LowerCaseAlphabet + $DecimalAlphabet + $SymbolAlphabet; break }
            'd' { return $DecimalAlphabet; break }
            'o' { return $OctalAlphabet; break }
            'b' { return $BinaryAlphabet; break }
            '!' { return $SymbolAlphabet; break }
            default { return $CharacterClass; break }
        }
    }

    Function Set-RandomCase ([String] $Character) {
        $Result = 0..1 | Get-Random

        if ($Result -eq 0) {
            return $Character.ToLower()
        } else {
            return $Character.ToUpper()
        }
    }

    Function Get-TemplatePassword ([String] $TemplateString) {
        $TemplatePassword = ''
        $AllGood = $true

        for ($c = 0; $c -lt $TemplateString.Length; $c++) {
            switch ($TemplateString[$c]) {
                
                '-' {
                    if ($TemplateString.Length - 1 -ne $c) {
                        $TemplatePassword += $TemplateString[$c + 1]
                        $c += 1
                    } else {
                        Write-Error 'Syntax error'
                        $AllGood = $false
                        break
                    }

                }
                '.' {
                    if ($TemplateString.Length - 1 -ne $c) {
                        $Pool = Get-Pool $TemplateString[$c + 1]
                        do {
                            $PasswordChar = ($Pool | Get-Random).ToLower()
                        } while (!(Approve $PasswordChar))

                        $TemplatePassword += $PasswordChar
                        $c += 1
                    } else {
                        Write-Error 'Syntax error'
                        $AllGood = $false
                        break
                    }
                }
                ':' {
                    if ($TemplateString.Length - 1 -ne $c) {
                        $Pool = Get-Pool $TemplateString[$c + 1]
                        do {
                            $PasswordChar = ($Pool | Get-Random).ToUpper()
                        } while (!(Approve $PasswordChar))

                        $TemplatePassword += $PasswordChar
                        $c += 1
                    } else {
                        Write-Error 'Syntax error'
                        $AllGood = $false
                        break
                    }
                }
                {'*', 'a', 'l', 'c', 'v', 'd', '!', 'h', 'b', 'o' -ccontains $_} {
                    $Pool = Get-Pool $TemplateString[$c]
                    do {
                        $PasswordChar = Set-RandomCase ($Pool | Get-Random)
                    } while (!(Approve $PasswordChar))

                    $TemplatePassword += $PasswordChar
                }
                default { $TemplatePassword += $TemplateString[$c] }
            }
        }
        if ($AllGood) {
            return $TemplatePassword
        } else {
            return $null
        }
    }


    $Password = ""
    
    if ($Template -eq '') {

        $Variations = 0

        if ($CustomPattern -ne '') {
            $Variations++
            foreach ($letter in $CustomPattern.GetEnumerator()) {
                if (!$TotalAlphabet.Contains($letter)) {
                    $TotalAlphabet += $letter
                }
            }
        } else {
            if ($Mode -eq "TotalMode") {
                if ($UseLowerCase) {
                    $Variations++
                    $TotalAlphabet += $LowerCaseAlphabet
            
                }
                if ($UseUpperCase) {
                    $Variations++
                    $TotalAlphabet += $UpperCaseAlphabet
            
                }
                if ($UseDecimalNumbers) {
                    $Variations++
                    $TotalAlphabet += $DecimalAlphabet
            
                }
                if ($UseSymbols) {
                    $Variations++
                    $TotalAlphabet += $SymbolAlphabet
                }
            } else {
                if ($UseLowerCase) {
                    $Variations++
                    $TotalAlphabet += ,$LowerCaseAlphabet
                }
                if ($UseUpperCase) {
                    $Variations++
                    $TotalAlphabet += ,$UpperCaseAlphabet
                }
                if ($UseDecimalNumbers) {
                    $Variations++
                    $TotalAlphabet += ,$DecimalAlphabet
                }
                if ($UseSymbols) {
                    $Variations++
                    $TotalAlphabet += ,$SymbolAlphabet
                }        
            }
        }

        if ($Variations -gt 0) {
            if ($Mode -eq "TotalMode" -or $CustomPattern -ne "") {
                for ($i = 0; $i -lt $Length;$i++) {
                    $index = Get-Random -Minimum 0 -Maximum $TotalAlphabet.Length

                    while (!(Approve $TotalAlphabet[$index])) {
                            $index = Get-Random -Minimum 0 -Maximum $TotalAlphabet.Length
                    }
                    Count $TotalAlphabet[$index]
                    $Password = $Password + $TotalAlphabet[$index]
                }
            } else {
                for ($i = 0; $i -lt $Length;$i++) {
                    $variation = $null

                    if ($Variations -gt 1) {
                        $variation = Get-Random -Minimum 0 -Maximum $Variations
                    } else {
                        $variation = 0
                    }
                    $index = Get-Random -Minimum 0 -Maximum $TotalAlphabet[$variation].Length
        
                    while (!(Approve $TotalAlphabet[$variation][$index])) {
                        $index = Get-Random -Minimum 0 -Maximum $TotalAlphabet[$variation].Length
                    }
                    Count $TotalAlphabet[$variation][$index]
                    $Password += $TotalAlphabet[$variation][$index]
                }
            }

            Write-Verbose ("LC:{0:P} UC:{1:P} NC:{2:P} SC:{3:P}" -f ($LCC / $Length), ($UCC / $Length), ($NC / $Length), ($SC / $Length))

        } else {
            Write-Error -Message "Invalid combination of parameters"
            return
        }
    } else {
        $Password = Get-TemplatePassword $Template
    }

    if ($PhoneticOutput) {
        $PhoneticPassword = ""
        for ($i = 0; $i -lt $Password.Length; $i++) {
            $PhoneticPassword += ConvertTo-Phonetic $Password[$i]
            $PhoneticPassword += ' '
        }
        $PhoneticPassword = $PhoneticPassword.TrimEnd()
        Write-Output $PhoneticPassword
    } else {
        Write-Output $Password
    }
}
