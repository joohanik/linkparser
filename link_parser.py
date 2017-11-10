# Copyright (C) 2017 Coresecurity
# Author : HanIk Joo (joohanik@coresec.co.kr)


import sys
import getopt
import time
import struct                 # struct module - Inerpret strings as packed binary data
from datetime import datetime, timedelta
from array import *

def main(argv):   
    if len(argv) < 1:
        Usage()
        exit()

    try:  # http://www.faqs.org/docs/diveintopython/kgp_commandline.html
        opts, args = getopt.getopt(argv, "hf:", ["help", "file="])   
    except getopt.GetoptError:
        Usage()
        exit()
    
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            Help()
            exit()
        elif opt in ("-f", "--file"):             
            try:                             
                LinkFileRawData = GetFileRawData(arg)     # File Check
            except:
                print 'Failed to file open.'               
                exit()        
            else:    
                if LinkFileRawData[0x04:0x08].encode('hex') != "01140200":  # Link File Signature Check
                    print "Incorrect Signature."
                    exit()
                print "\n[+] Starting Shell Link Parser 0.1 Beta at " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n"
                ShellLinkParser(LinkFileRawData)                                
                print "\n[+] Finishing Shell Link Parser\n"
                exit()
    Usage()
            

def Help():
    print "[*] Windows Shell Link Parser v0.1 Beta"
    print "[*] Copyright (C) 2013 Core Security Contributors\n"
    print "Usage : " + sys.argv[0] + " [OPTION] [LINK_FILE_NAME]"
    print "  -h  --help\n\tprint usage summary"
    print "  -f  --file\n\tuse specified link file\n"    
    
def DriveTypeParser(raw_data):
    DRIVE_UNKNOWN = 0
    DRIVE_NO_ROOT_DIR = 1
    DRIVE_REMOVABLE = 2
    DRIVE_FIXED = 3
    DRIVE_REMOTE = 4
    DRIVE_CDROM = 5
    DRIVE_RAMDISK = 6
    
    DriveType = dict()
    DriveType['raw'] = raw_data
    
    DriveType['DRIVE_UNKNOWN'] = False
    if DriveType['raw'] == DRIVE_UNKNOWN:
        DriveType['DRIVE_UNKNOWN'] = True
    
    DriveType['DRIVE_NO_ROOT_DIR'] = False
    if DriveType['raw'] == DRIVE_NO_ROOT_DIR:
        DriveType['DRIVE_NO_ROOT_DIR'] = True
    
    DriveType['DRIVE_REMOVABLE'] = False
    if DriveType['raw'] == DRIVE_REMOVABLE:
        DriveType['DRIVE_REMOVABLE'] = True
    
    DriveType['DRIVE_FIXED'] = False
    if DriveType['raw'] == DRIVE_FIXED:
        DriveType['DRIVE_FIXED'] = True
    
    DriveType['DRIVE_REMOTE'] = False
    if DriveType['raw'] == DRIVE_REMOTE:
        DriveType['DRIVE_REMOTE'] = True
    
    DriveType['DRIVE_CDROM'] = False
    if DriveType['raw'] == DRIVE_CDROM:
        DriveType['DRIVE_CDROM'] = True
        
    DriveType['DRIVE_RAMDISK'] = False
    if DriveType['raw'] == DRIVE_RAMDISK:
        DriveType['DRIVE_RAMDISK'] = True
    
    return DriveType

        
def LinkInfoFlagsParser(raw_data):
    VolumeIDAndLocalBasePath = 1 << 0
    CommonNetworkRelativeLinkAndPathSuffix = 1 << 1
    # print raw_data
    LinkInfoFlags = dict()
    LinkInfoFlags['raw'] = raw_data
    
    LinkInfoFlags['VolumeIDAndLocalBasePath']= False
    if LinkInfoFlags['raw'] & VolumeIDAndLocalBasePath != 0:
        LinkInfoFlags['VolumeIDAndLocalBasePath']= True
    
    LinkInfoFlags['CommonNetworkRelativeLinkAndPathSuffix']= False
    if LinkInfoFlags['raw'] & CommonNetworkRelativeLinkAndPathSuffix != 0:
        LinkInfoFlags['CommonNetworkRelativeLinkAndPathSuffix']= True
    
    return LinkInfoFlags
    
def FileAttributesFlagsParser(raw_data):
    FILE_ATTRIBUTE_READONLY = 1 << 0
    FILE_ATTRIBUTE_HIDDEN = 1 << 1
    FILE_ATTRIBUTE_SYSTEM = 1 << 2
    Reserved1 = 1 << 3
    FILE_ATTRIBUTE_DIRECTORY = 1 << 4
    FILE_ATTRIBUTE_ARCHIVE = 1 << 5
    Reserved2 = 1<< 6
    FILE_ATTRIBUTE_NORMAL = 1 << 7
    FILE_ATTRIBUTE_TEMPORARY = 1 << 8
    FILE_ATTRIBUTE_SPARSE_FILE = 1 << 9
    FILE_ATTRIBUTE_REPARSE_POINT = 1 << 10
    FILE_ATTRIBUTE_COMPRESSED = 1 << 11
    FILE_ATTRIBUTE_OFFLINE = 1 << 12
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 1 << 13
    FILE_ATTRIBUTE_ENCRYPTED = 1 << 14
    
    FileAttributesFlags = dict()
    FileAttributesFlags['raw'] = raw_data
    
    FileAttributesFlags['FILE_ATTRIBUTE_READONLY']= False
    if FileAttributesFlags['raw'] & FILE_ATTRIBUTE_READONLY != 0:
        FileAttributesFlags['FILE_ATTRIBUTE_READONLY']= True
    
    FileAttributesFlags['FILE_ATTRIBUTE_HIDDEN']= False
    if FileAttributesFlags['raw'] & FILE_ATTRIBUTE_HIDDEN != 0:
        FileAttributesFlags['FILE_ATTRIBUTE_HIDDEN']= True
    
    FileAttributesFlags['FILE_ATTRIBUTE_SYSTEM']= False
    if FileAttributesFlags['raw'] & FILE_ATTRIBUTE_SYSTEM != 0:
        FileAttributesFlags['FILE_ATTRIBUTE_SYSTEM']= True    

    FileAttributesFlags['Reserved1']= False
    if FileAttributesFlags['raw'] & Reserved1 != 0:
        FileAttributesFlags['Reserved1']= True    
        
    FileAttributesFlags['FILE_ATTRIBUTE_DIRECTORY']= False
    if FileAttributesFlags['raw'] &FILE_ATTRIBUTE_DIRECTORY != 0:
        FileAttributesFlags['FILE_ATTRIBUTE_DIRECTORY']= True    
    
    FileAttributesFlags['FILE_ATTRIBUTE_ARCHIVE']= False
    if FileAttributesFlags['raw'] &FILE_ATTRIBUTE_ARCHIVE != 0:
        FileAttributesFlags['FILE_ATTRIBUTE_ARCHIVE']= True    
        
    FileAttributesFlags['Reserved2']= False
    if FileAttributesFlags['raw'] &Reserved2 != 0:
        FileAttributesFlags['Reserved2']= True    
    
    FileAttributesFlags['FILE_ATTRIBUTE_NORMAL']= False
    if FileAttributesFlags['raw'] &FILE_ATTRIBUTE_NORMAL != 0:
        FileAttributesFlags['FILE_ATTRIBUTE_NORMAL']= True    
        
    FileAttributesFlags['FILE_ATTRIBUTE_TEMPORARY']= False
    if FileAttributesFlags['raw'] &FILE_ATTRIBUTE_TEMPORARY != 0:
        FileAttributesFlags['FILE_ATTRIBUTE_TEMPORARY']= True   
        
    FileAttributesFlags['FILE_ATTRIBUTE_SPARSE_FILE']= False
    if FileAttributesFlags['raw'] &FILE_ATTRIBUTE_SPARSE_FILE != 0:
        FileAttributesFlags['FILE_ATTRIBUTE_SPARSE_FILE']= True   
        
    FileAttributesFlags['FILE_ATTRIBUTE_REPARSE_POINT']= False
    if FileAttributesFlags['raw'] &FILE_ATTRIBUTE_REPARSE_POINT != 0:
        FileAttributesFlags['FILE_ATTRIBUTE_REPARSE_POINT']= True   
        
    FileAttributesFlags['FILE_ATTRIBUTE_COMPRESSED']= False
    if FileAttributesFlags['raw'] &FILE_ATTRIBUTE_COMPRESSED != 0:
        FileAttributesFlags['FILE_ATTRIBUTE_COMPRESSED']= True   
        
    FileAttributesFlags['FILE_ATTRIBUTE_OFFLINE']= False
    if FileAttributesFlags['raw'] &FILE_ATTRIBUTE_OFFLINE != 0:
        FileAttributesFlags['FILE_ATTRIBUTE_OFFLINE']= True   
        
    FileAttributesFlags['FILE_ATTRIBUTE_NOT_CONTENT_INDEXED']= False
    if FileAttributesFlags['raw'] &FILE_ATTRIBUTE_NOT_CONTENT_INDEXED != 0:
        FileAttributesFlags['FILE_ATTRIBUTE_NOT_CONTENT_INDEXED']= True   
        
    FileAttributesFlags['FILE_ATTRIBUTE_ENCRYPTED']= False
    if FileAttributesFlags['raw'] &FILE_ATTRIBUTE_ENCRYPTED != 0:
        FileAttributesFlags['FILE_ATTRIBUTE_ENCRYPTED']= True   
        
    return FileAttributesFlags

def FileTimeParser(hex_time_data):
    dt = hex_time_data[14:16] + hex_time_data[12:14] + hex_time_data[10:12] + hex_time_data[8:10] + hex_time_data[6:8] + hex_time_data[4:6] + hex_time_data[2:4] + hex_time_data[0:2]
    us = int(dt,16) / 10.
    return datetime(1601,1,1) + timedelta(microseconds=us)

def Usage():
    print "[*] Windows Shell Link Parser v0.1 Beta"
    print "[*] Contact to joohanik@gmail.com"
    print "[*] Copyright (C) 2013 Core Security Contributors\n"    
    print "Usage : " + sys.argv[0] + " [OPTION] [LINK_FILE_NAME]"
    print "Try '-h' or '--help' option for more information"
    

def GetFileRawData(filename):
    Hlinkfile = open(filename, 'rb')        # open the file in Read and Binary mode
    linkfile = Hlinkfile.read()
    Hlinkfile.close()
    return linkfile

def LinkFlagsParser(raw_data):
    HasLinkTargetIDList = 1 << 0    
    HasLinkInfo = 1 << 1
    HasName = 1 << 2
    HasRelativePath = 1 << 3
    HasWorkingDir = 1 << 4
    HasArguments = 1 << 5
    HasIconLocation = 1 << 6
    IsUnicode = 1 << 7
    ForceNoLinkInfo = 1 << 8
    HasExpString = 1 << 9
    RunInSeparateProcess = 1 << 10
    Unused1 = 1 << 11
    HasDarwinID = 1 << 12
    RunAsUser = 1 << 13
    HasExpIcon = 1 << 14
    NoPidlAlizs = 1 << 15
    Unused2 = 1 << 16
    RunWithShimLayer = 1 << 17
    ForceNoLinkTrack = 1 << 18
    EnableTargetMetadata = 1 << 19
    DisableLinkPathTracking = 1 << 20
    DisableKnownFolderTracking = 1 << 21
    DisableKnownFolderAlias = 1 << 22
    AllowLinkToLink = 1 << 23
    UnaliasOnSave = 1 << 24
    PreferEnvironmentPath = 1 << 25
    KeepLocalIDListForUNCTarget = 1 << 26

    LinkFlags = dict()
    LinkFlags['raw'] = raw_data
    
    LinkFlags['HasLinkTargetIDList']= False
    if LinkFlags['raw'] & HasLinkTargetIDList != 0:
        LinkFlags['HasLinkTargetIDList']= True
    
    LinkFlags['HasLinkInfo']= False
    if LinkFlags['raw'] & HasLinkInfo != 0:
        LinkFlags['HasLinkInfo']= True
        
    LinkFlags['HasName']= False
    if LinkFlags['raw'] & HasName != 0:
        LinkFlags['HasName']= True
        
    LinkFlags['HasRelativePath']= False
    if LinkFlags['raw'] & HasRelativePath != 0:
        LinkFlags['HasRelativePath']= True
        
    LinkFlags['HasWorkingDir']= False
    if LinkFlags['raw'] & HasWorkingDir != 0:
        LinkFlags['HasWorkingDir']= True
        
    LinkFlags['HasArguments']= False
    if LinkFlags['raw'] & HasArguments != 0:
        LinkFlags['HasArguments']= True
        
    LinkFlags['HasIconLocation']= False
    if LinkFlags['raw'] & HasIconLocation != 0:
        LinkFlags['HasIconLocation']= True
        
    LinkFlags['IsUnicode']= False
    if LinkFlags['raw'] & IsUnicode != 0:
        LinkFlags['IsUnicode']= True
        
    LinkFlags['ForceNoLinkInfo']= False
    if LinkFlags['raw'] & ForceNoLinkInfo != 0:
        LinkFlags['ForceNoLinkInfo']= True
        
    LinkFlags['HasExpString']= False
    if LinkFlags['raw'] & HasExpString != 0:
        LinkFlags['HasExpString']= True
        
    LinkFlags['RunInSeparateProcess']= False
    if LinkFlags['raw'] & RunInSeparateProcess != 0:
        LinkFlags['RunInSeparateProcess']= True
        
    LinkFlags['Unused1']= False
    if LinkFlags['raw'] & Unused1 != 0:
        LinkFlags['Unused1']= True
        
    LinkFlags['HasDarwinID']= False
    if LinkFlags['raw'] & HasDarwinID != 0:
        LinkFlags['HasDarwinID']= True
        
    LinkFlags['RunAsUser']= False
    if LinkFlags['raw'] & RunAsUser != 0:
        LinkFlags['RunAsUser']= True
        
    LinkFlags['HasExpIcon']= False
    if LinkFlags['raw'] & HasExpIcon != 0:
        LinkFlags['HasExpIcon']= True
    
    LinkFlags['NoPidlAlizs']= False
    if LinkFlags['raw'] & NoPidlAlizs != 0:
        LinkFlags['NoPidlAlizs']= True
        
    LinkFlags['Unused2']= False
    if LinkFlags['raw'] & Unused2 != 0:
        LinkFlags['Unused2']= True
        
    LinkFlags['RunWithShimLayer']= False
    if LinkFlags['raw'] & RunWithShimLayer != 0:
        LinkFlags['RunWithShimLayer']= True
        
    LinkFlags['ForceNoLinkTrack']= False
    if LinkFlags['raw'] & ForceNoLinkTrack != 0:
        LinkFlags['ForceNoLinkTrack']= True
        
    LinkFlags['EnableTargetMetadata']= False
    if LinkFlags['raw'] & EnableTargetMetadata != 0:
        LinkFlags['EnableTargetMetadata']= True
        
    LinkFlags['DisableLinkPathTracking']= False
    if LinkFlags['raw'] & DisableLinkPathTracking != 0:
        LinkFlags['DisableLinkPathTracking']= True
        
    LinkFlags['DisableKnownFolderTracking']= False
    if LinkFlags['raw'] & DisableKnownFolderTracking != 0:
        LinkFlags['DisableKnownFolderTracking']= True
        
    LinkFlags['DisableKnownFolderAlias']= False
    if LinkFlags['raw'] & DisableKnownFolderAlias != 0:
        LinkFlags['DisableKnownFolderAlias']= True        
        
    LinkFlags['AllowLinkToLink']= False
    if LinkFlags['raw'] & AllowLinkToLink != 0:
        LinkFlags['AllowLinkToLink']= True        
        
    LinkFlags['UnaliasOnSave']= False
    if LinkFlags['raw'] & UnaliasOnSave != 0:
        LinkFlags['UnaliasOnSave']= True        
        
    LinkFlags['PreferEnvironmentPath']= False
    if LinkFlags['raw'] & PreferEnvironmentPath != 0:
        LinkFlags['PreferEnvironmentPath']= True     
        
    LinkFlags['KeepLocalIDListForUNCTarget']= False
    if LinkFlags['raw'] & KeepLocalIDListForUNCTarget != 0:
        LinkFlags['KeepLocalIDListForUNCTarget']= True     

    return LinkFlags


def ShellLinkParser(LinkFileRawData):
    
# ===================================================================================================
# SHELL_LINK = SHELL_LINK_HEADER [LINKTARGET_IDLIST] [LINKINFO] [STRING_DATA] *EXTRA_DATA
# ===================================================================================================
     
        
# ===================================================================================================
# SHELL_LINK_HEADER Structure Parsing, Offset 0x0-0x4C
# ===================================================================================================
    CurrentRawPointer = 0x0     # Start offset of SHELL_LINK_HEADER structur
    P1 = CurrentRawPointer
    ShellLinkHeaderSize = struct.unpack("<I", LinkFileRawData[P1+0x0:P1+0x04])[0]              # "<I" is Unsigned Integer Type, Little Endian

    P2 = P1 + 0x4    # Start offset of CLSID inspection  
    LinkCLSID = ["", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""]
    for i in range(0x0, 0x10):        
        LinkCLSID[i] = LinkFileRawData[P2+i:P2+i+1].encode('hex').upper()
    LinkFlags = LinkFlagsParser(struct.unpack("<I", LinkFileRawData[P1+0x14:P1+0x18])[0])
    FileAttributesFlags = FileAttributesFlagsParser(struct.unpack("I", LinkFileRawData[P1+0x18:P1+0x1C])[0]) 
    CreationTime = FileTimeParser(LinkFileRawData[P1+0x1C:P1+0x24].encode('hex'))
    AccessTime = FileTimeParser(LinkFileRawData[P1+0x24:P1+0x2C].encode('hex'))
    WriteTime = FileTimeParser(LinkFileRawData[P1+0x2C:P1+0x34].encode('hex'))
    FileSize = struct.unpack("I",LinkFileRawData[P1+0x34:P1+0x38])[0]        
    print "  [SHELL_LINK_HEADER structure]"
    print "\tHeaderSize : " + str(ShellLinkHeaderSize) + " (Bytes)"
    print "\tLinkCLSID(Class Identifier, Static) : %s%s%s%s-%s%s-%s%s-%s%s-%s%s%s%s%s%s" % (LinkCLSID[3],
                                                                                            LinkCLSID[2],
                                                                                            LinkCLSID[1],
                                                                                            LinkCLSID[0],
                                                                                            LinkCLSID[4],                                                                                            
                                                                                            LinkCLSID[5],
                                                                                            LinkCLSID[6],
                                                                                            LinkCLSID[7],
                                                                                            LinkCLSID[8],
                                                                                            LinkCLSID[9],
                                                                                            LinkCLSID[0xA],
                                                                                            LinkCLSID[0xB],
                                                                                            LinkCLSID[0xC],
                                                                                            LinkCLSID[0xD],
                                                                                            LinkCLSID[0xE],
                                                                                            LinkCLSID[0xF])       
    #print "\tLinkFlags : "
    for x in LinkFlags.keys():
        if LinkFlags[x] == True:
            if x == 'raw':
                continue
            #print "\t\t%s is True"%x
  
    #print "\tFileAttributesFlags : "    
    for x in FileAttributesFlags.keys():
        if FileAttributesFlags[x] == True:
            if x == 'raw':
                continue
            #print "\t\t%s is True"%x
            
    print "\tTime Information : "
    print "\t\tCreationTime(Target File) is " + str(CreationTime) + " [UTC]"
    print "\t\tAccessTime(Target File) is " + str(AccessTime) + " [UTC]"
    print "\t\tWriteTime(Target File) is " + str(WriteTime) + " [UTC]"
    print "\tFileSize(Target File) : %d (Bytes)"%FileSize
    CurrentRawPointer = CurrentRawPointer + ShellLinkHeaderSize
    #print "--- Offset : %d"%CurrentRawPointer
    
    
# ==================================================================================================== 
# Optional Structure Parsing - LINKTARGET_IDLIST, Offset 0x4c - ?
#    LINKTARGET_IDLIST = IDListSize(2Bytes) + IDList(Variable)
#    IDList = ItemIDList(Variable) + TerminalID(2Bytes, 0x0000)
#    ItemIDList = (ItemIDSize(2Bytes) + Data(Variable)) + (ItemIDSize(2Bytes) + Data(Variable)) ...
# ==================================================================================================== 
    if LinkFlags['HasLinkTargetIDList'] == True:
        P1 = CurrentRawPointer                           # Start Offset of LINKTARGET_IDLIST Structure
        ItemIDListCount = 0x0
        #print "\n  [LINKTARGET_IDLIST structure]"
        IDListSize = struct.unpack("h", LinkFileRawData[P1:P1+2])[0]        
        #print "\tIDListSize : %d (Bytes)"%IDListSize
        P2 = P1 + 2                        # Start Offset of IDList
        P1 = P1 + IDListSize + 2           # End Offset of LINKTARGET_IDLIST
        while P2 < P1:
            ItemIDSize = struct.unpack("h", LinkFileRawData[P2:P2+2])[0]
            if ItemIDSize == 0:
                break
            ItemIDListCount += 1
            P2 += ItemIDSize
        #print "\tItemIDListCount : %d"%ItemIDListCount
        CurrentRawPointer = CurrentRawPointer + 0x2 + IDListSize
        #print "--- Offset : %d"%CurrentRawPointer

# =================================================================================================================
# Optional Structure Parsing - LINKINFO
#    LINKINFO = LinkInfoSize(4Bytes) + LinkInfoHeaderSize(4Bytes) + LinkInfoFlags(4Bytes) +
#               VolumeIDOffset(4Bytes) + LocalBasePathOffset(4Bytes) + CommonNetworkRelativeLinkOffset(4Bytes) +
#               CommonPathSuffixOffset(4Bytes) + LocalBasePathOffsetUnicode(optional) + 
#               CommonPathSuffixOffsetUnicode(optiona) + VolumeID(variable) ... LocalBasePath(variable) ...
#               
#    VolumeID = VolumeIDSize(4Bytes) + DriveType(4Bytes) + DriveSerialNumber(4Bytes) + VolumeLavelOffset(4Bytes) +
#               VolumeLabelOffsetUnicode(optional) + Data(Variable) ...
# =================================================================================================================
    if LinkFlags['HasLinkInfo'] == True:
        P1 = CurrentRawPointer
        print "\n  [LINKINFO structure]"
        LinkInfoSize = struct.unpack("I", LinkFileRawData[P1:P1+4])[0]       # P1 is pointer what start offset of LINKINFO
        print "\tLinkInfoSize : %d (Bytes)"%LinkInfoSize
        LinkInfoHeaderSize = struct.unpack("I", LinkFileRawData[P1+4:P1+8])[0]
        print "\tLinkInfoHeaderSize : %d (Bytes)"%LinkInfoHeaderSize
        LinkInfoFlags = LinkInfoFlagsParser(struct.unpack("<I", LinkFileRawData[P1+0x8:P1+0xC])[0])
        #print "\tLinkInfoFlags : "
        for x in LinkInfoFlags.keys():
            if LinkInfoFlags[x] == True:
                if x == 'raw':
                    continue
                #print "\t\t%s is True"%x
        if LinkInfoFlags['VolumeIDAndLocalBasePath'] == True:          # VolumeID and LocalBasePath inspection 
            LocalBasePathOffset = struct.unpack("I", LinkFileRawData[P1+0x10:P1+0x14])[0]
            # print "\tLocalBasePathOffset : 0x%x (Bytes)"%LocalBasePathOffset
            P2 = P1 + LocalBasePathOffset                               # P2 is general purpose pointer
            LocalBasePath = ""
            
            # Add LocalBasePath Size Calculating Code ..
            while LinkFileRawData[P2:P2+1] != "\0":
                LocalBasePath = LocalBasePath + LinkFileRawData[P2:P2+1]
                P2 += 1
            print "\tLocalBasePath : %s"%LocalBasePath
            VolumeIDOffset = struct.unpack("I", LinkFileRawData[P1+0xC:P1+0x10])[0]
            #print "\tVolumeIDOffset : 0x%x (Bytes)"%VolumeIDOffset
            print "\t[VolumeID structure]"
            P2 = P1 + VolumeIDOffset               # P2 is start offset of VolumeID Structure
            DriveType = DriveTypeParser(struct.unpack("<I", LinkFileRawData[P2+4:P2+8])[0])
            for x in DriveType.keys():
                if DriveType[x] == True:
                    if x == 'raw':
                        continue
                    print "\t\tDriveType(Target Drive) : %s"%x           
            
            #DriveSerialNumber = struct.unpack('<I', LinkFileRawData[P2+0x8:P2+0xC])[0]
            #print "\t\tDriveSerialNumber(Target Drive) : %X"%DriveSerialNumber

            DriveSerialNumber = ["", "", "", ""]
            DriveSerialNumber[0] = LinkFileRawData[P2+0x8:P2+0x9].encode('hex').upper()
            DriveSerialNumber[1] = LinkFileRawData[P2+0x9:P2+0xA].encode('hex').upper()            
            DriveSerialNumber[2] = LinkFileRawData[P2+0xA:P2+0xB].encode('hex').upper()
            DriveSerialNumber[3] = LinkFileRawData[P2+0xB:P2+0xC].encode('hex').upper()
            print "\t\tDriveSerialNumber(Target Drive) : %s%s-%s%s" % (DriveSerialNumber[3],
                                                                       DriveSerialNumber[2],
                                                                       DriveSerialNumber[1],
                                                                       DriveSerialNumber[0])
               
            VolumeLabelOffset = struct.unpack('<I', LinkFileRawData[P2+0xC:P2+0x10])[0]
            #print "\tVolumeLabelOffset : 0x%x (Bytes)"%VolumeLabelOffset
            P3 = P2 + VolumeLabelOffset               # P3 is start offset of VolumeLabel
    
            VolumeLabel = ""
            while LinkFileRawData[P3:P3+1] != "\0":
                VolumeLabel = VolumeLabel + LinkFileRawData[P3:P3+1]
                P3 += 1
            print "\t\tVolumeLabel(Target Volume) : %s"%VolumeLabel
                                                                  
        CurrentRawPointer = CurrentRawPointer + LinkInfoSize
        #print "--- Offset : %d"%CurrentRawPointer
        
# =================================================================================================================
# Optional Structure Parsing - STRING_DATA Structure
#    STRING_DATA = [NAME_SRING] [RELATIVE_PATH] [WORKING_DIR] [COMMAND_LINE_ARGUMENTS] [ICON_LOCATION]
#    All StringData structures have the following structure
#      STRING_DATA = CountCharacters(2Bytes) + String(Variable)
# =================================================================================================================
    if LinkFlags['HasName'] == True:
        #print "\nHasName Parsing"
        P1 = CurrentRawPointer
        CountCharacters = struct.unpack("h", LinkFileRawData[P1:P1+2])[0]
        CurrentRawPointer = CurrentRawPointer + 0x2 + CountCharacters*0x2
        #print "--- Offset : %d"%CurrentRawPointer
        
    if LinkFlags['HasRelativePath']== True:
        #print "\nHas RelativePath Parsing"
        P1 = CurrentRawPointer
        CountCharacters = struct.unpack("h", LinkFileRawData[P1:P1+2])[0]
        CurrentRawPointer = CurrentRawPointer + 0x2 + CountCharacters*0x2
        #print "--- Offset : %d"%CurrentRawPointer      
       
    if LinkFlags['HasWorkingDir']== True:
        #print "\nHasWorkingDir Parsing"
        P1 = CurrentRawPointer
        CountCharacters = struct.unpack("h", LinkFileRawData[P1:P1+2])[0]
        CurrentRawPointer = CurrentRawPointer + 0x2 + CountCharacters*0x2
        #print "--- Offset : %d"%CurrentRawPointer
       
    if LinkFlags['HasArguments']== True:
        #print "\nHasArguments Parsing"
        P1 = CurrentRawPointer
        CountCharacters = struct.unpack("h", LinkFileRawData[P1:P1+2])[0]
        CurrentRawPointer = CurrentRawPointer + 0x2 + CountCharacters*0x2
        #print "--- Offset : %d"%CurrentRawPointer
       
    if LinkFlags['HasIconLocation']== True:
        #print "\nHasIconLocation Parsing"
        P1 = CurrentRawPointer
        CountCharacters = struct.unpack("h", LinkFileRawData[P1:P1+2])[0]
        CurrentRawPointer = CurrentRawPointer + 0x2 + CountCharacters*0x2
        #print "--- Offset : %d"%CurrentRawPointer
    #print "--- Offset : %d"%CurrentRawPointer

# =================================================================================================================
# Optional Structure Parsing - EXTRA_DATA
#   EXTRA_DATA = *EXTRA_DATA_BLOCK TERMINAL_BLOCK
#   EXTRA_DATA_BLOCK = CONSOLE_PROPS / CONSOLE_FE_PROPS / DARWIN_PROPS /
#                      ENVIRONMENT_PROPS / ICON_ENVIRONMENT_PROPS /
#                      KNOWN_FOLDER_PROPS / PROPERTY_STORE_PROPS /
#                      SHIM_PROPS / SPECIAL_FOLDER_PROPS /
#                      TRACKER_PROPS / VISTA_AND_ABOVE_IDLIST_PROPS
#   
#   (TRACKER_PROPS) TrackerDataBlock = BlockSize(4Bytes) + BlocSignature(4Bytes) + Length(4Bytes) + Version(4Bytes)
#                   + MachineID(variable) + Droid(32Bytes) + DroidBirth(32Bytes)
# =================================================================================================================
    P1 = CurrentRawPointer
    DataBlockSize = struct.unpack("I", LinkFileRawData[P1:P1+4])[0]
    while True:   # TrackerDataBlock(TRACKER_PROPS) or TERMINAL_BLOCK Searching ...        
        if DataBlockSize == 0x60:    
            break
        if DataBlockSize < 0x04:
            break
        CurrentRawPointer = CurrentRawPointer + DataBlockSize
        P1 = CurrentRawPointer
        DataBlockSize = struct.unpack("I", LinkFileRawData[P1:P1+4])[0]                
    if DataBlockSize == 0x60:          # TrackerDataBlock Size == 0x60 
        print "\n  [TrackerDataBlock structure]"
        P2 = P1 + 0x10        # P2 = Start offset of MachineID
        MachineID = ""
        while LinkFileRawData[P2:P2+1] != "\0":
                MachineID = MachineID + LinkFileRawData[P2:P2+1]
                P2 += 1
        print "\tMachineID : %s"%MachineID
        P2 = P1 + 0x5A        # P2 = Start offset of NIC's MAC Address
        MAC_Address = [ "", "", "", "", "", ""]
        MAC_Address[0] = LinkFileRawData[P2:P2+1].encode('hex').upper()
        MAC_Address[1] = LinkFileRawData[P2+1:P2+2].encode('hex').upper()
        MAC_Address[2] = LinkFileRawData[P2+2:P2+3].encode('hex').upper()
        MAC_Address[3] = LinkFileRawData[P2+3:P2+4].encode('hex').upper()
        MAC_Address[4] = LinkFileRawData[P2+4:P2+5].encode('hex').upper()
        MAC_Address[5] = LinkFileRawData[P2+5:P2+6].encode('hex').upper()
        print "\tMAC Address : %s-%s-%s-%s-%s-%s" % (MAC_Address[0],
                                                     MAC_Address[1],
                                                     MAC_Address[2],
                                                     MAC_Address[3],
                                                     MAC_Address[4],
                                                     MAC_Address[5])
   


# ====================================================================================================    
# __Main__ Code 
# ====================================================================================================
if __name__ == "__main__":                 # __name__ is Global Variable
    main(sys.argv[1:])                     # Chop first Argument off and pass rest of the list

    
