linkparser
==========
Microsoft Windows OS linkfile(Shortcut) parser


## How to use
If you want to parse only one linkfile, command as follow:
	$ python link_parser.py -f [Path to linkfile]

## Example
	$ python link_parser.py -f ./linkfile_sample/USBDumper.lnk

	[+] Starting Shell Link Parser 0.1 Beta at 2017-11-11 00:08:53

	  [SHELL_LINK_HEADER structure]
		HeaderSize : 76 (Bytes)
		LinkCLSID(Class Identifier, Static) : 00021401-0000-0000-C000-000000000046
		Time Information :
			CreationTime(Target File) is 2009-05-30 01:16:49.437500 [UTC]
			AccessTime(Target File) is 2009-05-30 01:19:39.671876 [UTC]
			WriteTime(Target File) is 2009-05-30 01:16:50.421876 [UTC]
		FileSize(Target File) : 57662 (Bytes)

	  [LINKINFO structure]
		LinkInfoSize : 63 (Bytes)
		LinkInfoHeaderSize : 28 (Bytes)
		LocalBasePath : C:\USBDumper.rar
		[VolumeID structure]
			DriveType(Target Drive) : DRIVE_FIXED
			DriveSerialNumber(Target Drive) : 780B-53E4
			VolumeLabel(Target Volume) :

	  [TrackerDataBlock structure]
		MachineID : kjwkor-7clfzy6d
		MAC Address : 00-0C-29-F8-FB-23

	[+] Finishing Shell Link Parser

## Contacts
linkparser was written by joohanik(joohanik@coresec.co.kr)
Feel free to send me an E-mail if you have any questions.