for ($i = 0; $i -le $Args.Count; $i ++)
{
    If ($Args[$i] -ceq "-o" ){
        If($Args[$i+1] -cmatch "^.+[^o]$"){
            $linking = $true
            $output  = $Args[$i+1]
        }
    }
}

If($linking){

  .\avr-g++.exe @Args
  .\faegen.exe $output
  .\avr-g++.exe @Args __fae_data.o
}Else{
  .\avr-g++.exe @Args
}
