# linkparser
Microsoft Windows OS linkfile(Shortcut) parser


nigguui-MacBook-Pro-2:linkparser niggu$ python link_parser.py --help
[*] Windows Shell Link Parser v0.1 Beta
[*] Copyright (C) 2013 Core Security Contributors

Usage : link_parser.py [OPTION] [LINK_FILE_NAME]
  -h  --help
	print usage summary
  -f  --file
	use specified link file


nigguui-MacBook-Pro-2:linkparser niggu$ python link_parser.py -f ./linkfilesample/
...

nigguui-MacBook-Pro-2:linkparser niggu$ python link_parser.py -f ./linkfilesample/USBDumper.lnk

[+] Starting Shell Link Parser 0.1 Beta at 2017-11-10 11:58:52

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

nigguui-MacBook-Pro-2:linkparser niggu$