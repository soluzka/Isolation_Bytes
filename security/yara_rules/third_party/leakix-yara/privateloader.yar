rule privateloader : loader 
{
  meta:
    author =                    "andretavare5"
    org =                       "BitSight"
    date =                      "2022-06-06"
    description =               "PrivateLoader pay-per-install malware"
    yarahub_author_twitter =    "@andretavare5"
    yarahub_reference_link =    "https://tavares.re/blog/2022/06/06/hunting-privateloader-pay-per-install-service"
    yarahub_malpedia_family =   "win.privateloader"
    yarahub_uuid =              "5916c441-16b1-42b7-acaa-114c06296f38"
    yarahub_license =           "CC BY-NC-SA 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp =  "TLP:WHITE"
    yarahub_reference_md5 =     "8f70a0f45532261cb4df2800b141551d"
    
  strings:
    $code = {66 0F EF (4?|8?)} // pxor xmm(1/0) - str chunk decryption
    $str = "Content-Type: application/x-www-form-urlencoded\r\n" wide ascii
   	$ua1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36" wide ascii
    $ua2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36" wide ascii
                              
  condition:
    uint16(0) == 0x5A4D and // MZ
    $str and
    any of ($ua*) and
    #code > 100
}