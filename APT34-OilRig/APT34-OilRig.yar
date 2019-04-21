rule APT34_ASPX_base_shell{
meta:
  author = "Moath Maharmeh https://github.com/iomoath"
  last_updated = "2019-04-21"
  hash1 = "faa3a80456b3a074fad3eb5c39293a51"
  hash2 = "4f3672ec2ce751dc3f92bb9913474b4c"
  description = "Catches APT34 ASPX base shell"

strings:
  $s1 = "Request.Params[\"d\"], signature = Request.Params[\"s\"], parameters = Request.Params[\"p\"], ks = Request.Params[\"ks\"];"
  $s2 = "5I5Mai8UN5PaPqq+hIr5QCvd9OUykjonZmMVlg7yUsnFKf0FeTtlb55Eb5zxI/OHJj1JzPCjbyMvpPMmdxg4fSnVZBhYuTE+0+9Ierl3V41Tw53BtO22ktDqWY5m40/Zpdgn2sPESrqBif6/HbnccgRM5iPx8qAq3qV3gfxTOfl4jDlG6n8iuhBYNetmHRFOW3C4/7qIUYp0GS0vfx+jb0sZIjrSCy6J1mxMy/1QgSwGOSbcnJCh0Nijn006DVX2rTDoKY97JfXs5h+Ac3KW3vQldkyFdLIOpRbbA4yOMJ6XEX6O7/n51t3GkD+rFUwmNtpVnMPGdIoxc0QyHdu2DQ=="
condition:
   1 of them
}



rule APT34_ASPX_HyperShell{
meta:
  author = "Moath Maharmeh https://github.com/iomoath"
  last_updated = "2019-04-21"
  hash = "ed9df0d451824d2f17e85c3837667ac5"
  description = "Catches APT34 HyperShell"

strings:
  $s1 = "wwNY50sX8od1PqYGbuHawKW2hf57MSEIR96hD4jwHSlcOrpaLZYeE3B1GGwKAAXK5Jx13iuIG"
  $s2 = "Vp4w9JVASbHtSjvETdhc9iAP09R2zHfzaCmX13yQCi7xbcE6nItIaxoqXkq/q2CKhQrlHTCZxcH"
  $s3 = "u8P1OFD8TZhEXQPsp4OvucWj2uWvjpsxWxzKMGNGHVE6MF8VIayNn8q5m1sNUYX3VsR3"
  $s4 = "HtmlEncode(\"NxKK<TjWN^lv-$*UZ|Z-H;cGL(O>7a\")"
condition:
   3 of them
}


rule APT34_ASPX_HyperShell_Local{
meta:
  author = "Moath Maharmeh https://github.com/iomoath"
  last_updated = "2019-04-21"
  hash1 = "1d7f710ff16d7eeea07949037dc90fc0"
  hash2 = "74536f55f3b9dd034b8e08ccc772e546"
  hash3 = "01208115690dc2c42664e1983ff8202d"
  hash4 = "8eba7c97f611b9b0ed3e714904a5e023"

  description = "Catches APT34 HyperShell Local"

strings:
  $s1 = "\"----sdfERASDGsdf342GA\";"
  $s2 = "getIPFromNbt="
  $s3 = "SaveLog(unpack("
  $s4 = "nen, upb, upd, del, don"
  $s5 = "J3ugYdknpax1ZbHB2QILB5NS6dVa0iUD0mhhBPv0Srw"
  $s6 = "815Wbii+WzJXZwvm4SXrkIFLnLJ9+ZcJDOoLeiL711w="
  $s7 = "ModuleName.mdltar4"
  $s8 = "command($('#inpCmd"
  $s9 = "DVsd1YT+t32whUqKfof/OW+nHkrnPR2g+slM4EfaZI8"
  $s10 = "ModuleName.mdlhb"
  $s11 = "tyruee.exe"

condition:
   3 of them
}


rule APT34_ASPX_HyperShell_Server{
meta:
  author = "Moath Maharmeh https://github.com/iomoath"
  last_updated = "2019-04-21"
  hash1 = "024a57209b941ef8dbe8a4c8fa93eddd"
  hash2 = "81e047b76994428d6b579593dd822b5e"
  hash3 = "c7901a03240c1b207ef67a018f0facdc"
  hash4 = "a280191a8a2cadebedae4519fce913d9"
  hash5 = "622e324a2a796b7dd73a5397218965f3"
  hash6 = "701dce1e70c2acddff42d04537bb3f92"
  hash7 = "0e53fd33039fabd8dd399c78846aff19"
  hash7 = "a0678149b32a44231794c13a91249f3b"
  hash8 = "71737940068029146e410e8c4bdb9ada"
  hash9 = "75ad2623afba4f95b3b538ef50b99058"
  hash10 = "af67394c4314f2985de024f3b10d8582"
  hash11 = "4386d4fc6e11f968d56242b3de55f206"
  hash12 = "ad7e4d743813ceee6e14f3649a3f566d"

  description = "Catches APT34 HyperShell Server"

strings:
  $s1 = "zpT27yKM#a6xQ2#Yj4JB6VS3Qcl8U^*zMVR3MuVuVjWTgI1LeM4mFyHHAT^OnF#*"
  $s2 = "+Zgi2BaVbaVAFH6LqpHFtrjfMxPgYpLbt6RmxkDda6k="
  $s3 = "pro#=#{0}#|#cmd#=#{1}#|#sav#=#{2}#|#vir#=#{3}#|#nen#=#{4}#|#don#=#{5}#|#tfil#=#{6}#|#ttar#=#{7}#|#ttim#=#{8}|#sqc#=#{9}|#sqq#=#{10}|#exadd#=#{11}"
  $s4 = "pro)?\"cmd.exe\":pro"
  $s5 = "baseVir=t[\"baseVir\"]"
  $s6 = "case\"sqq\":sqq=a(sqq,fb(data3[1]));break;"
  $s7 = "case\"cmd\":cmd=a(cmd,fb(data3[1]));break;"
  $s8 = "case method.view:view(fb(t[\"view\"]));break;"
  $s9 = "sqlQuery=7,explorer=8,getsize"
  $s10 = "del {0} 2>&1"
  $s11 = "temp\\KMSHFX0023"
  $s12 = "tb(tfil),tb(ttar)"
  $s13 = "case method.commandAjax:command(fb(t[\"cmd\"]));break"
condition:
   3 of them
}


rule APT34_ASPX_HyperShell_Downloader{
meta:
  author = "Moath Maharmeh https://github.com/iomoath"
  last_updated = "2019-04-21"
  hash = "89a7a4a57c4289cb6926f5dfb8fe31c3"
  description = "Catches APT34 HyperShell Downloader"

strings:
  $s1 = "HttpContext.Current.Request.Form[\"sport\"]"
  $s2 = "Current.Request.Cookies[\"fqrspt\"]"
  $s3 = "process.StartInfo.FileName = \"cm\" + \"d.e\" + \"xe\";"
  $s4 = "Current.Request.Form[\"balls\"]"
  $s5 = "Request.Files[\"woods\"]"
  $s6 = "OOOLefHUgIk$Alin2dpdiW3Bn&x*z26x94V*XECjn7j4J0Q4dA13YOo#5nh@2Kvh"
condition:
   3 of them
}



rule APT34_Glimpse_Agent{
meta:
  author = "Moath Maharmeh https://github.com/iomoath"
  last_updated = "2019-04-21"
  hash = "6e86c57385d26a59c0df1580454b9967"
  description = "Catches APT34 Glimpse Agent version 2.2"

strings:
  $s1 = "aa_lock_file_address_bb"
  $s2 = "$aa_main_folder_bb + \"\\lock\";"
  $s3 = "${global:$aa_done_box_bb} = ${global:$aa_root_path_bb}"
  $s4 = "$aa_file_done_address_bb = $aa_tmpAddress_bb -replace \"receivebox\""
condition:
   2 of them
}


rule APT34_Glimpse_Agent_1{
meta:
  author = "Moath Maharmeh https://github.com/iomoath"
  last_updated = "2019-04-21"
  hash = "688a165fc64b3c9ad19022f581599c91"
  description = "Catches APT34 Glimpse Agent 2.3"

strings:
  $s1 = "-replace \"receivebox\", \"sendbox\";"
  $s2 = "= nslookup.exe"
  $s3 = "2>&1\") | % {Try { $_ | cmd.exe | Out-String }Catch { $_ | Out-String }}"
  $s4 = "| ? { $_.trim() -ne "
condition:
   2 of them
}

rule APT34_Poison_Frog_Agent{
meta:
  author = "Moath Maharmeh https://github.com/iomoath"
  last_updated = "2019-04-21"
  hash = "5e17061bf2dce87d402ddd8531abb49f"
  description = "Catches APT34 Poison Frog agent"

strings:
  $s1 = "JENDQSA9ICJteWxlZnRoZWFydC5jb20iOw0KJEREQSA9IGdldC13bWlvYmplY3QgV2luMzJfQ29tcHV0ZXJTeXN0ZW1Qcm9kdWN0ICB8IFNlbGVjdC1PYmplY3QgLUV4cGFuZFByb3BlcnR5IFVVSUQgfCAleyAiYXRhZzEyIiArICRfLnJlcGxhY2UoJy0nLCcnKSB9fCAley"
  $s3 = "cSAicHJ0Iil7JEtLQSA9ICRHR0FbMV0gKyAiIjt9DQoJCWlmKCRHR0FbMF0gLWVxICJkb"
  $s4 = "Powershell.exe -exec bypass -file"
  $s5 = "${global:$dns_ag}"
condition:
   2 of them
}

rule APT34_Glimpse_Poison_Frog_Control_Panel{
meta:
  author = "Moath Maharmeh https://github.com/iomoath"
  last_updated = "2019-04-21"
  hash = "4b7a9aac2c54e1deab2020f58dd1b840"
  description = "Catches APT34 Glimpse control panel"

strings:
    $s1 = "386be98ce7c7955f92dc060779ed7613"
    $s2 = "require('flat-file-db')"
    $s3 = "state = \"dnsActive\";" fullword
    $s4 = "state = \"httpActive\";"

condition:
   2 of them
}

rule APT34_Glimpse_Webmask_ICAP{
meta:
  author = "Moath Maharmeh https://github.com/iomoath"
  last_updated = "2019-04-21"
  hash = "9e7c29837da25c37dfa51004d02cd92c"
  description = "Catches APT34 Webmask server ICAP"

strings:
    $s1 = "re.search('([^&]*%s[^=]*=[^&]+)"
    $s2 = "pwd', 'upassword', 'login_password"
    $s3 = "['authorization'][0].split"
condition:
   3 of them
}
