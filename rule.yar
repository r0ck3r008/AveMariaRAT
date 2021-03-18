rule practical2_rat {
	meta:
		description = "Detect Practical2.exe RAT"
		author = "Naman Arora"
		date = "2021-03-17"
		hash = "9633d0564a2b8f1b4c6e718ae7ab48be921d435236a403cf5e7ddfbfd4283382"
	strings:
		$pdb = "C:\\Users\\W7H64\\Desktop\\VCSamples-master\\VC2010Samples\\ATL\\General\\AtlCon\\bitcoin coinjoin op.pdb" fullword ascii
		$ops = {c6 04 0a c2 b8 01 00 00 00 c1 e0 00 8b 4d 84 c6 04 01 10 b8 01 00 00 00 d1 e0 8b 4d 84 c6 04 01 00 b8 01 00 00 00 6b c8 03 8b 55 84 c6 04 0a 90}
	condition:
		uint16(0) == 0x5a4d and filesize < 1500MB and all of them
}
