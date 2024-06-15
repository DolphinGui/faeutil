for ($i = 0; $i -le $Args.Count; $i ++)
{
    If ($Args[$i] -ceq "-o" ){
        If($Args[$i+1] -cmatch "^.+[^o]$"){
            $linking = $true
            $output  = $Args[$i+1]
        }
    }
}

$bin=$PSScriptRoot

If($linking){
  & $bin\avr-g++.exe @Args
  & $bin\faegen.exe $output
  & $bin\avr-g++.exe @Args __fae_data.o
}Else{
  & $bin\avr-g++.exe @Args
}
