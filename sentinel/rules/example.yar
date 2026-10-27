rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
    condition:
        filesize < 1KB and $eicar
}

rule Suspicious_Script_Downloader
{
    meta:
        description = "Script that downloads and runs content with an encoded command"
    strings:
        $dl  = "DownloadString" nocase
        $enc = "-enc" nocase
        $iex = "IEX" nocase
    condition:
        2 of them
}
