import "pe"

rule MAL_Loader_Smokeloader_Feb24 {
	meta:
		Author = "CTI_MNEMO"
		Date = "2024-02-15"
		Description = "Detects SmokeLoader's sample viewed in the wild"
		sha1 = "2014FAF33C80FD5A5A187C99A202444263445DD0"
	
	strings:
		$Entrypoint = {13 30 03 00 5F 01 00 00 01 00 00 11 7E 03 00 00 04 2C 0D 28 11 00 00 06 2C 06 16 28}
		$h1 = {58 00 4F 00 52 00 49 00 41 00 49 00 5A 00 43 00 4E 00 49 00 57 00 77 00}
		
		$s1 = "d21cbe21e38b385a41a68c5e6dd32f4c" wide
		$s2 = "toolspub1" wide
		$s3 = "get_StartInfo" fullword
	
	condition:
		uint16(0) == 0x5A4D
		and pe.version_info["OriginalFilename"] contains "latestroc.exe"
		and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744"
		and all of them

}
