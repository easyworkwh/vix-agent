# -*- coding:utf-8 -*- 
'''
/* **********************************************************
 * Copyright (c) 2004-2008 VMware, Inc.  All rights reserved. -- VMware Confidential
 * **********************************************************/

/*
 * This is the Python interface to the VIX API.
 * This is platform-independent.
 */
'''

import sys
import os
import string
from ctypes import *

import logging

osname = os.name
DYLIBPATH = "/usr/lib/vmware-vix/lib/VIServer-2.0.0/64bit"
DYLIBFILENAME = "libvix.so"
if osname == "nt":
    DYLIBPATH = "C:\\Program Files (x86)\\VMware\\VMware VIX\\Workstation-8.0.0-and-vSphere-5.0.0\\32bit"
    DYLIBFILENAME = "vix.dll"


class Vix(object):
    '''
    Reconstruct the entry to handle VMware Server by the vix interface
    '''
    # After power on vm, wait for vm tools for 5 minutes
    TOOLS_TIMEOUT = 300
    # Following const variables are referring to the source code from vix.h in VIX API
    
    VIX_INVALID_HANDLE   = 0

    #These are the types of handles.
    VIX_HANDLETYPE_NONE                 = 0
    VIX_HANDLETYPE_HOST                 = 2
    VIX_HANDLETYPE_VM                   = 3
    VIX_HANDLETYPE_NETWORK              = 5
    VIX_HANDLETYPE_JOB                  = 6
    VIX_HANDLETYPE_SNAPSHOT             = 7
    VIX_HANDLETYPE_PROPERTY_LIST        = 9
    VIX_HANDLETYPE_METADATA_CONTAINER   = 11


    #The error codes are returned by all public VIX routines.
    VIX_OK                                       = 0

    #General errors */
    VIX_E_FAIL                                   = 1
    VIX_E_OUT_OF_MEMORY                          = 2
    VIX_E_INVALID_ARG                            = 3
    VIX_E_FILE_NOT_FOUND                         = 4
    VIX_E_OBJECT_IS_BUSY                         = 5
    VIX_E_NOT_SUPPORTED                          = 6
    VIX_E_FILE_ERROR                             = 7
    VIX_E_DISK_FULL                              = 8
    VIX_E_INCORRECT_FILE_TYPE                    = 9
    VIX_E_CANCELLED                              = 10
    VIX_E_FILE_READ_ONLY                         = 11
    VIX_E_FILE_ALREADY_EXISTS                    = 12
    VIX_E_FILE_ACCESS_ERROR                      = 13
    VIX_E_REQUIRES_LARGE_FILES                   = 14
    VIX_E_FILE_ALREADY_LOCKED                    = 15
    VIX_E_VMDB                                   = 16
    VIX_E_NOT_SUPPORTED_ON_REMOTE_OBJECT         = 20
    VIX_E_FILE_TOO_BIG                           = 21
    VIX_E_FILE_NAME_INVALID                      = 22
    VIX_E_ALREADY_EXISTS                         = 23
    VIX_E_BUFFER_TOOSMALL                        = 24
    VIX_E_OBJECT_NOT_FOUND                       = 25
    VIX_E_HOST_NOT_CONNECTED                     = 26
    VIX_E_UNFINISHED_JOB                         = 29


    #Handle Errors
    VIX_E_INVALID_HANDLE                         = 1000
    VIX_E_NOT_SUPPORTED_ON_HANDLE_TYPE           = 1001
    VIX_E_TOO_MANY_HANDLES                       = 1002

    #XML errors
    VIX_E_NOT_FOUND                              = 2000
    VIX_E_TYPE_MISMATCH                          = 2001
    VIX_E_INVALID_XML                            = 2002

    #VM Control Errors
    VIX_E_TIMEOUT_WAITING_FOR_TOOLS              = 3000
    VIX_E_UNRECOGNIZED_COMMAND                   = 3001
    VIX_E_OP_NOT_SUPPORTED_ON_GUEST              = 3003
    VIX_E_PROGRAM_NOT_STARTED                    = 3004
    VIX_E_CANNOT_START_READ_ONLY_VM              = 3005
    VIX_E_VM_NOT_RUNNING                         = 3006
    VIX_E_VM_IS_RUNNING                          = 3007
    VIX_E_CANNOT_CONNECT_TO_VM                   = 3008
    VIX_E_POWEROP_SCRIPTS_NOT_AVAILABLE          = 3009
    VIX_E_NO_GUEST_OS_INSTALLED                  = 3010
    VIX_E_VM_INSUFFICIENT_HOST_MEMORY            = 3011
    VIX_E_SUSPEND_ERROR                          = 3012
    VIX_E_VM_NOT_ENOUGH_CPUS                     = 3013
    VIX_E_HOST_USER_PERMISSIONS                  = 3014
    VIX_E_GUEST_USER_PERMISSIONS                 = 3015
    VIX_E_TOOLS_NOT_RUNNING                      = 3016
    VIX_E_GUEST_OPERATIONS_PROHIBITED            = 3017
    VIX_E_ANON_GUEST_OPERATIONS_PROHIBITED       = 3018
    VIX_E_ROOT_GUEST_OPERATIONS_PROHIBITED       = 3019
    VIX_E_MISSING_ANON_GUEST_ACCOUNT             = 3023
    VIX_E_CANNOT_AUTHENTICATE_WITH_GUEST         = 3024
    VIX_E_UNRECOGNIZED_COMMAND_IN_GUEST          = 3025
    VIX_E_CONSOLE_GUEST_OPERATIONS_PROHIBITED    = 3026
    VIX_E_MUST_BE_CONSOLE_USER                   = 3027
    VIX_E_VMX_MSG_DIALOG_AND_NO_UI               = 3028
    VIX_E_NOT_ALLOWED_DURING_VM_RECORDING        = 3029
    VIX_E_NOT_ALLOWED_DURING_VM_REPLAY           = 3030
    VIX_E_OPERATION_NOT_ALLOWED_FOR_LOGIN_TYPE   = 3031
    VIX_E_LOGIN_TYPE_NOT_SUPPORTED               = 3032
    VIX_E_EMPTY_PASSWORD_NOT_ALLOWED_IN_GUEST    = 3033
    VIX_E_INTERACTIVE_SESSION_NOT_PRESENT        = 3034
    VIX_E_INTERACTIVE_SESSION_USER_MISMATCH      = 3035          
    VIX_E_UNABLE_TO_REPLAY_VM                    = 3039


    #VM Errors  
    VIX_E_VM_NOT_FOUND                           = 4000
    VIX_E_NOT_SUPPORTED_FOR_VM_VERSION           = 4001
    VIX_E_CANNOT_READ_VM_CONFIG                  = 4002
    VIX_E_TEMPLATE_VM                            = 4003
    VIX_E_VM_ALREADY_LOADED                      = 4004
    VIX_E_VM_ALREADY_UP_TO_DATE                  = 4006

    #Property Errors 
    VIX_E_UNRECOGNIZED_PROPERTY                  = 6000
    VIX_E_INVALID_PROPERTY_VALUE                 = 6001
    VIX_E_READ_ONLY_PROPERTY                     = 6002
    VIX_E_MISSING_REQUIRED_PROPERTY              = 6003
    VIX_E_INVALID_SERIALIZED_DATA                = 6004

    #Completion Errors */
    VIX_E_BAD_VM_INDEX                           = 8000

    #Message errors */
    VIX_E_INVALID_MESSAGE_HEADER                 = 10000
    VIX_E_INVALID_MESSAGE_BODY                   = 10001

    #Snapshot errors */
    VIX_E_SNAPSHOT_INVAL                         = 13000
    VIX_E_SNAPSHOT_DUMPER                        = 13001
    VIX_E_SNAPSHOT_DISKLIB                       = 13002
    VIX_E_SNAPSHOT_NOTFOUND                      = 13003
    VIX_E_SNAPSHOT_EXISTS                        = 13004
    VIX_E_SNAPSHOT_VERSION                       = 13005
    VIX_E_SNAPSHOT_NOPERM                        = 13006
    VIX_E_SNAPSHOT_CONFIG                        = 13007
    VIX_E_SNAPSHOT_NOCHANGE                      = 13008
    VIX_E_SNAPSHOT_CHECKPOINT                    = 13009
    VIX_E_SNAPSHOT_LOCKED                        = 13010
    VIX_E_SNAPSHOT_INCONSISTENT                  = 13011
    VIX_E_SNAPSHOT_NAMETOOLONG                   = 13012
    VIX_E_SNAPSHOT_VIXFILE                       = 13013
    VIX_E_SNAPSHOT_DISKLOCKED                    = 13014
    VIX_E_SNAPSHOT_DUPLICATEDDISK                = 13015
    VIX_E_SNAPSHOT_INDEPENDENTDISK               = 13016
    VIX_E_SNAPSHOT_NONUNIQUE_NAME                = 13017
    VIX_E_SNAPSHOT_MEMORY_ON_INDEPENDENT_DISK    = 13018

    #Host Errors */
    VIX_E_HOST_DISK_INVALID_VALUE                = 14003
    VIX_E_HOST_DISK_SECTORSIZE                   = 14004
    VIX_E_HOST_FILE_ERROR_EOF                    = 14005
    VIX_E_HOST_NETBLKDEV_HANDSHAKE               = 14006
    VIX_E_HOST_SOCKET_CREATION_ERROR             = 14007
    VIX_E_HOST_SERVER_NOT_FOUND                  = 14008
    VIX_E_HOST_NETWORK_CONN_REFUSED              = 14009
    VIX_E_HOST_TCP_SOCKET_ERROR                  = 14010
    VIX_E_HOST_TCP_CONN_LOST                     = 14011
    VIX_E_HOST_NBD_HASHFILE_VOLUME               = 14012
    VIX_E_HOST_NBD_HASHFILE_INIT                 = 14013
   
    #Disklib errors */
    VIX_E_DISK_INVAL                             = 16000
    VIX_E_DISK_NOINIT                            = 16001
    VIX_E_DISK_NOIO                              = 16002
    VIX_E_DISK_PARTIALCHAIN                      = 16003
    VIX_E_DISK_NEEDSREPAIR                       = 16006
    VIX_E_DISK_OUTOFRANGE                        = 16007
    VIX_E_DISK_CID_MISMATCH                      = 16008
    VIX_E_DISK_CANTSHRINK                        = 16009
    VIX_E_DISK_PARTMISMATCH                      = 16010
    VIX_E_DISK_UNSUPPORTEDDISKVERSION            = 16011
    VIX_E_DISK_OPENPARENT                        = 16012
    VIX_E_DISK_NOTSUPPORTED                      = 16013
    VIX_E_DISK_NEEDKEY                           = 16014
    VIX_E_DISK_NOKEYOVERRIDE                     = 16015
    VIX_E_DISK_NOTENCRYPTED                      = 16016
    VIX_E_DISK_NOKEY                             = 16017
    VIX_E_DISK_INVALIDPARTITIONTABLE             = 16018
    VIX_E_DISK_NOTNORMAL                         = 16019
    VIX_E_DISK_NOTENCDESC                        = 16020
    VIX_E_DISK_NEEDVMFS                          = 16022
    VIX_E_DISK_RAWTOOBIG                         = 16024
    VIX_E_DISK_TOOMANYOPENFILES                  = 16027
    VIX_E_DISK_TOOMANYREDO                       = 16028
    VIX_E_DISK_RAWTOOSMALL                       = 16029
    VIX_E_DISK_INVALIDCHAIN                      = 16030
    VIX_E_DISK_KEY_NOTFOUND                      = 16052 # metadata key is not found
    VIX_E_DISK_SUBSYSTEM_INIT_FAIL               = 16053
    VIX_E_DISK_INVALID_CONNECTION                = 16054
    VIX_E_DISK_ENCODING                          = 16061
    VIX_E_DISK_CANTREPAIR                        = 16062
    VIX_E_DISK_INVALIDDISK                       = 16063
    VIX_E_DISK_NOLICENSE                         = 16064

    #Crypto Library Errors */
    VIX_E_CRYPTO_UNKNOWN_ALGORITHM               = 17000
    VIX_E_CRYPTO_BAD_BUFFER_SIZE                 = 17001
    VIX_E_CRYPTO_INVALID_OPERATION               = 17002
    VIX_E_CRYPTO_RANDOM_DEVICE                   = 17003
    VIX_E_CRYPTO_NEED_PASSWORD                   = 17004
    VIX_E_CRYPTO_BAS_PASSWORD                    = 17005
    VIX_E_CRYPTO_NOT_IN_DICTIONARY               = 17006
    VIX_E_CRYPTO_NO_CRYPTO                       = 17007
    VIX_E_CRYPTO_ERROR                           = 17008
    VIX_E_CRYPTO_BAD_FORMAT                      = 17009
    VIX_E_CRYPTO_LOCKED                          = 17010
    VIX_E_CRYPTO_EMPTY                           = 17011
    VIX_E_CRYPTO_KEYSAFE_LOCATOR                 = 17012

    #Remoting Errors. */
    VIX_E_CANNOT_CONNECT_TO_HOST                 = 18000
    VIX_E_NOT_FOR_REMOTE_HOST                    = 18001
    VIX_E_INVALID_HOSTNAME_SPECIFICATION         = 18002
    
    #creen Capture Errors. */
    VIX_E_SCREEN_CAPTURE_ERROR                   = 19000
    VIX_E_SCREEN_CAPTURE_BAD_FORMAT              = 19001
    VIX_E_SCREEN_CAPTURE_COMPRESSION_FAIL        = 19002
    VIX_E_SCREEN_CAPTURE_LARGE_DATA              = 19003

    #Guest Errors */
    VIX_E_GUEST_VOLUMES_NOT_FROZEN               = 20000
    VIX_E_NOT_A_FILE                             = 20001
    VIX_E_NOT_A_DIRECTORY                        = 20002
    VIX_E_NO_SUCH_PROCESS                        = 20003
    VIX_E_FILE_NAME_TOO_LONG                     = 20004

    # Wrapper Errors */
    VIX_E_WRAPPER_WORKSTATION_NOT_INSTALLED      = 22001
    VIX_E_WRAPPER_VERSION_NOT_FOUND              = 22002
    VIX_E_WRAPPER_SERVICEPROVIDER_NOT_FOUND      = 22003

    # VIX Property Type
    VIX_PROPERTYTYPE_ANY             = 0
    VIX_PROPERTYTYPE_INTEGER         = 1
    VIX_PROPERTYTYPE_STRING          = 2
    VIX_PROPERTYTYPE_BOOL            = 3
    VIX_PROPERTYTYPE_HANDLE          = 4
    VIX_PROPERTYTYPE_INT64           = 5
    VIX_PROPERTYTYPE_BLOB            = 6

    # VIX Property ID's
    VIX_PROPERTY_NONE                                  = 0

    # Properties used by several handle types. */
    VIX_PROPERTY_META_DATA_CONTAINER                   = 2

    #VIX_HANDLETYPE_HOST properties */
    VIX_PROPERTY_HOST_HOSTTYPE                         = 50
    VIX_PROPERTY_HOST_API_VERSION                      = 51

    #VIX_HANDLETYPE_VM properties */
    VIX_PROPERTY_VM_NUM_VCPUS                          = 101
    VIX_PROPERTY_VM_VMX_PATHNAME                       = 103 
    VIX_PROPERTY_VM_VMTEAM_PATHNAME                    = 105 
    VIX_PROPERTY_VM_MEMORY_SIZE                        = 106
    VIX_PROPERTY_VM_READ_ONLY                          = 107
    VIX_PROPERTY_VM_IN_VMTEAM                          = 128
    VIX_PROPERTY_VM_POWER_STATE                        = 129
    VIX_PROPERTY_VM_TOOLS_STATE                        = 152
    VIX_PROPERTY_VM_IS_RUNNING                         = 196
    VIX_PROPERTY_VM_SUPPORTED_FEATURES                 = 197
    VIX_PROPERTY_VM_IS_RECORDING                       = 236
    VIX_PROPERTY_VM_IS_REPLAYING                       = 237

    #Result properties; these are returned by various procedures */
    VIX_PROPERTY_JOB_RESULT_ERROR_CODE                 = 3000
    VIX_PROPERTY_JOB_RESULT_VM_IN_GROUP                = 3001
    VIX_PROPERTY_JOB_RESULT_USER_MESSAGE               = 3002
    VIX_PROPERTY_JOB_RESULT_EXIT_CODE                  = 3004
    VIX_PROPERTY_JOB_RESULT_COMMAND_OUTPUT             = 3005
    VIX_PROPERTY_JOB_RESULT_HANDLE                     = 3010
    VIX_PROPERTY_JOB_RESULT_GUEST_OBJECT_EXISTS        = 3011
    VIX_PROPERTY_JOB_RESULT_GUEST_PROGRAM_ELAPSED_TIME = 3017
    VIX_PROPERTY_JOB_RESULT_GUEST_PROGRAM_EXIT_CODE    = 3018
    VIX_PROPERTY_JOB_RESULT_ITEM_NAME                  = 3035
    VIX_PROPERTY_JOB_RESULT_FOUND_ITEM_DESCRIPTION     = 3036
    VIX_PROPERTY_JOB_RESULT_SHARED_FOLDER_COUNT        = 3046
    VIX_PROPERTY_JOB_RESULT_SHARED_FOLDER_HOST         = 3048
    VIX_PROPERTY_JOB_RESULT_SHARED_FOLDER_FLAGS        = 3049
    VIX_PROPERTY_JOB_RESULT_PROCESS_ID                 = 3051
    VIX_PROPERTY_JOB_RESULT_PROCESS_OWNER              = 3052
    VIX_PROPERTY_JOB_RESULT_PROCESS_COMMAND            = 3053
    VIX_PROPERTY_JOB_RESULT_FILE_FLAGS                 = 3054
    VIX_PROPERTY_JOB_RESULT_PROCESS_START_TIME         = 3055
    VIX_PROPERTY_JOB_RESULT_VM_VARIABLE_STRING         = 3056
    VIX_PROPERTY_JOB_RESULT_PROCESS_BEING_DEBUGGED     = 3057
    VIX_PROPERTY_JOB_RESULT_SCREEN_IMAGE_SIZE          = 3058
    VIX_PROPERTY_JOB_RESULT_SCREEN_IMAGE_DATA          = 3059
    VIX_PROPERTY_JOB_RESULT_FILE_SIZE                  = 3061
    VIX_PROPERTY_JOB_RESULT_FILE_MOD_TIME              = 3062 

    #Event properties; these are sent in the moreEventInfo for some events. */
    VIX_PROPERTY_FOUND_ITEM_LOCATION                   = 4010

    # VIX_HANDLETYPE_SNAPSHOT properties */
    VIX_PROPERTY_SNAPSHOT_DISPLAYNAME                  = 4200   
    VIX_PROPERTY_SNAPSHOT_DESCRIPTION                  = 4201
    VIX_PROPERTY_SNAPSHOT_POWERSTATE                   = 4205
    VIX_PROPERTY_SNAPSHOT_IS_REPLAYABLE                = 4207

    '''
    These are events that may be signalled by calling a procedure
    of type VixEventProc.
    '''
    VIX_EVENTTYPE_JOB_COMPLETED          = 2
    VIX_EVENTTYPE_JOB_PROGRESS           = 3
    VIX_EVENTTYPE_FIND_ITEM              = 8
    VIX_EVENTTYPE_CALLBACK_SIGNALLED     = 2  #Deprecated - Use VIX_EVENTTYPE_JOB_COMPLETED instead.

    '''
    These are the property flags for each file.
    '''

    VIX_FILE_ATTRIBUTES_DIRECTORY       = 0x0001
    VIX_FILE_ATTRIBUTES_SYMLINK         = 0x0002
    
    '''
    Procedures of this type are called when an event happens on a handle.
    '''
    '''
    VIX Host --
    '''
    VIX_HOSTOPTION_USE_EVENT_PUMP        = 0x0008
    VIX_SERVICEPROVIDER_DEFAULT               = 1
    VIX_SERVICEPROVIDER_VMWARE_SERVER         = 2
    VIX_SERVICEPROVIDER_VMWARE_WORKSTATION    = 3
    VIX_SERVICEPROVIDER_VMWARE_VI_SERVER      = 10

    '''
    VIX_API_VERSION tells VixHost_Connect to use the latest API version 
    that is available for the product specified in the VixServiceProvider 
    parameter.
    '''
    VIX_API_VERSION      = -1
    
    '''
    VM Search
    '''
    VIX_FIND_RUNNING_VMS         = 1
    VIX_FIND_REGISTERED_VMS      = 4
    
    '''
    Event pump
    '''
    VIX_PUMPEVENTOPTION_NONE = 0
    
    '''
    PropertyList --
    '''
    '''
    VIX VM --
    This describes the persistent configuration state of a single VM. The VM may or may not be running.
    '''

    VIX_VMPOWEROP_NORMAL                      = 0
    VIX_VMPOWEROP_FROM_GUEST                  = 0x0004
    VIX_VMPOWEROP_SUPPRESS_SNAPSHOT_POWERON   = 0x0080
    VIX_VMPOWEROP_LAUNCH_GUI                  = 0x0200
    VIX_VMPOWEROP_START_VM_PAUSED             = 0x1000

    '''
    Power operations
    '''
    VIX_VMDELETE_DISK_FILES     = 0x0002

    '''
    This is the state of an individual VM.
    '''
    VIX_POWERSTATE_POWERING_OFF    = 0x0001
    VIX_POWERSTATE_POWERED_OFF     = 0x0002
    VIX_POWERSTATE_POWERING_ON     = 0x0004
    VIX_POWERSTATE_POWERED_ON      = 0x0008
    VIX_POWERSTATE_SUSPENDING      = 0x0010
    VIX_POWERSTATE_SUSPENDED       = 0x0020
    VIX_POWERSTATE_TOOLS_RUNNING   = 0x0040
    VIX_POWERSTATE_RESETTING       = 0x0080
    VIX_POWERSTATE_BLOCKED_ON_MSG  = 0x0100
    VIX_POWERSTATE_PAUSED          = 0x0200
    VIX_POWERSTATE_RESUMING        = 0x0800

    VIX_TOOLSSTATE_UNKNOWN           = 0x0001
    VIX_TOOLSSTATE_RUNNING           = 0x0002
    VIX_TOOLSSTATE_NOT_INSTALLED     = 0x0004

    '''
    These flags describe optional functions supported by different types of VM.
    '''

    VIX_VM_SUPPORT_SHARED_FOLDERS       = 0x0001
    VIX_VM_SUPPORT_MULTIPLE_SNAPSHOTS   = 0x0002
    VIX_VM_SUPPORT_TOOLS_INSTALL        = 0x0004
    VIX_VM_SUPPORT_HARDWARE_UPGRADE     = 0x0008
    
    '''
    These are special names for an anonymous user and the system administrator.
    The password is ignored if you specify these.
    '''
    '''
    VixVM_LoginInGuest option flags.
    '''
    VIX_LOGIN_IN_GUEST_REQUIRE_INTERACTIVE_ENVIRONMENT      = 0x08

    '''
    Guest Process functions
    '''
    VIX_RUNPROGRAM_RETURN_IMMEDIATELY   = 0x0001
    VIX_RUNPROGRAM_ACTIVATE_WINDOW      = 0x0002
   
    '''
    Guest Variable Functions
    '''
    VIX_VM_GUEST_VARIABLE            = 1
    VIX_VM_CONFIG_RUNTIME_ONLY       = 2
    VIX_GUEST_ENVIRONMENT_VARIABLE   = 3

    ''' 
    Snapshot functions that operate on a VM
    '''
    VIX_SNAPSHOT_REMOVE_CHILDREN    = 0x0001
    VIX_SNAPSHOT_INCLUDE_MEMORY     = 0x0002

    '''
    Shared Folders Functions
    '''
    
    '''
    These are the flags describing each shared folder.
    '''
    VIX_SHAREDFOLDER_WRITE_ACCESS     = 0x04
    
    '''
    Screen Capture
    '''
    VIX_CAPTURESCREENFORMAT_PNG            = 0x01
    VIX_CAPTURESCREENFORMAT_PNG_NOCOMPRESS = 0x02
    
    '''
    VM Cloning --
    '''
    VIX_CLONETYPE_FULL       = 0
    VIX_CLONETYPE_LINKED     = 1
    
    #####################################################

    def __init__(self):
        '''
        Constructor
        '''
        self.url = ""
        self.username = ""
        self.password = ""
        self.vmfolder = "null"
        self.vmuser = "null"
        self.vmpassword = "null"
        self.isConnected = False
        dylibfilepath = os.path.join(DYLIBPATH, DYLIBFILENAME)
        print dylibfilepath
        self.vix = vix = cdll.LoadLibrary(dylibfilepath)
        self.VixHost_Connect = self.vix.VixHost_Connect
        self.VixHost_Connect.argtypes = [c_int, c_int, c_char_p, c_int, c_char_p, c_char_p, c_int, c_int, c_void_p, c_void_p ]
        self.VixJob_Wait = self.vix.VixJob_Wait
        self.VixJob_Wait.argtypes = [c_int, c_int, c_void_p, c_int]
        self.VixJob_Wait2 = self.vix.VixJob_Wait
        self.VixJob_Wait2.argtypes = [c_int, c_int]
        self.Vix_GetVMPowerState = self.vix.Vix_GetProperties
        self.Vix_GetVMPowerState.argtypes = [c_int, c_int, c_void_p, c_int]
        #self.VixVM_GetNamedSnapshot = self.vix.VixVM_GetNamedSnapshot
        #self.VixVM_GetNamedSnapshot = [c_int, c_char_p, c_void_p]
        self.VixVM_GetRootSnapshot = self.vix.VixVM_GetRootSnapshot
        self.VixVM_GetRootSnapshot.argtypes = [c_int, c_int, c_void_p]

    def Connect(self, hostname = None, hostport = 0, username = None, password = None):
        self.jobHandle = Vix.VIX_INVALID_HANDLE
        self.vmHandle = Vix.VIX_INVALID_HANDLE
        self.hostHandle = Vix.VIX_INVALID_HANDLE
        self.jobHandle = self.VixHost_Connect(Vix.VIX_API_VERSION,
            Vix.VIX_SERVICEPROVIDER_VMWARE_VI_SERVER,
            hostname,
            hostport,
            username,
            password,
            0,
            Vix.VIX_INVALID_HANDLE,
            None,
            None);
        hostHandle = c_int()        
        err = self.VixJob_Wait(self.jobHandle, Vix.VIX_PROPERTY_JOB_RESULT_HANDLE,
            byref(hostHandle), Vix.VIX_PROPERTY_NONE)
        self.hostHandle = hostHandle.value
        self.vix.Vix_ReleaseHandle(self.jobHandle)
        if err != Vix.VIX_OK:
            raise Exception("VixHost_Connect Failed")
    
    def connecthost(self, url, username, userpassword):
        try:
            self.Connect(url, 0, username, userpassword)
            return True
        except Exception, e:
            logging.error(e)
        return False
    
    def disconnecthost(self):
        try:
            self.Disconnect()
        except Exception, e:
            logging.error(e)
    
    def Open(self, vmxFile):
        self.jobHandle = self.vix.VixVM_Open(self.hostHandle, vmxFile, None, None)
        
        vmHandle = c_int()
        err = self.VixJob_Wait(self.jobHandle, Vix.VIX_PROPERTY_JOB_RESULT_HANDLE,
            byref(vmHandle), Vix.VIX_PROPERTY_NONE)
        self.vix.Vix_ReleaseHandle(self.jobHandle);
        
        self.vmHandle = vmHandle.value
        
        if err != Vix.VIX_OK:
            raise Exception("VixVM_Open Failed")
    
    def locatevm(self, vmfolder, vmuser = None, vmpassword = None):
        try:
            self.vmfolder = vmfolder
            self.vmuser = vmuser
            self.vmpassword = vmpassword
            self.Open(self.vmfolder)
            return True
        except Exception, e:
            logging.error(e)
        return False
    
    def registevm(self, vmxpath):
        try:
            self.jobHandle = self.vix.VixHost_RegisterVM(self.hostHandle, vmxpath, None, None)
            err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
            self.vix.Vix_ReleaseHandle(self.jobHandle)
            
            if err != Vix.VIX_OK:
                logging.error("Vix_VM_Register Failed")
                return False
            return True            
        except Exception, e:
            logging.error(e)
        return False
    
    def unregistevm(self, vmxpath):
        try:
            self.jobHandle = self.vix.VixHost_UnregisterVM(self.hostHandle, vmxpath, None, None)
            err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
            self.vix.Vix_ReleaseHandle(self.jobHandle)
            
            if err != Vix.VIX_OK:
                logging.error("Vix_VM_Register Failed")
                return False
            return True            
        except Exception, e:
            logging.error(e)
        return False
    
    def poweronvm(self):
        try:
            self.PowerOn()
            return True
        except Exception, e:
            logging.error(e)
        return False
    
    def poweroffvm(self):
        try:
            self.PowerOff()
            return True
        except Exception, e:
            logging.error(e)
        return False

    def PowerOn(self):
        self.jobHandle = self.vix.VixVM_PowerOn(self.vmHandle, Vix.VIX_VMPOWEROP_NORMAL,
            Vix.VIX_INVALID_HANDLE, None, None);
        err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
        self.vix.Vix_ReleaseHandle(self.jobHandle);
        
        if err != Vix.VIX_OK:
            raise Exception("VixVM_PowerOn Failed")
        
    def PowerOff(self):
        self.jobHandle = self.vix.VixVM_PowerOff(self.vmHandle, Vix.VIX_VMPOWEROP_NORMAL,
            None, None);
        err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
        self.vix.Vix_ReleaseHandle(self.jobHandle);
        
        if err != Vix.VIX_OK:
            raise Exception("VixVM_PowerOff Failed")
    
    def getvmpowerstate(self, vmxFile):
        try:
            self.jobHandle = self.vix.VixVM_Open(self.hostHandle, vmxFile, None, None)
            vmHandle = c_int()
            err = self.VixJob_Wait(self.jobHandle, Vix.VIX_PROPERTY_JOB_RESULT_HANDLE, byref(vmHandle), Vix.VIX_PROPERTY_NONE)
            self.vix.Vix_ReleaseHandle(self.jobHandle);
        
            self.vmHandle = vmHandle.value
        
            if err != Vix.VIX_OK:
                raise Exception("VixVM_Open Failed")
            vmpowerstate = c_void_p(10)
            vmpowerstate_pointer = c_char_p("None")
            err = self.jobHandle = self.Vix_GetVMPowerState(self.vmHandle, Vix.VIX_PROPERTY_VM_POWER_STATE, vmpowerstate_pointer, Vix.VIX_PROPERTY_NONE)
            
            print "length %d"%len(vmpowerstate_pointer.value)
            print "|"
            #print int(vmpowerstate_pointer.value)
            for i in range(len(vmpowerstate_pointer.value)):
                print ord(vmpowerstate_pointer.value[i])
            print "|"
            '''
            for i in range(len(vmpowerstate_pointer.value)):
                print "%d, %x"%(i, hex(vmpowerstate_pointer.value[i]))
            '''
            print "3"
            #print "#### %d"%vmpowerstate
            if err == Vix.VIX_OK:
                return vmpowerstate
        except Exception, e:
            print e
        return None
            
    
    def GetVMHandle(self):
        return self.vmHandle

    def CreateSnapshot(self, name, description = None):
        self.jobHandle = self.vix.VixVM_CreateSnapshot(self.vmHandle, name,
            description, 0, Vix.VIX_INVALID_HANDLE, None, None)
        print "test 1 ", self.vmHandle
        vmHandle = c_int()
        #err = self.VixJob_Wait(self.snapshotHandle, Vix.VIX_PROPERTY_JOB_RESULT_HANDLE, byref(vmHandle), Vix.VIX_PROPERTY_NONE)
        err = self.VixJob_Wait(self.jobHandle, Vix.VIX_PROPERTY_JOB_RESULT_HANDLE, byref(vmHandle), Vix.VIX_PROPERTY_NONE)
        self.vix.Vix_ReleaseHandle(self.jobHandle);
        self.vmHandle = vmHandle.value
        print "test 2 ", vmHandle.value
        
        if err != Vix.VIX_OK:
            raise Exception("VixVM_CreateSnapshot Failed")
    
    def RevertToNamedSnapshot(self, name):
        self.GetNamedSnapshot(name)
        self.RevertToSnapshot()
    
    def RevertToSnapshot(self):
        # get snapshot handle
        
        self.jobHandle = self.vix.VixVM_RevertToSnapshot(self.vmHandle,
            self.snapshotHandle, 0, Vix.VIX_INVALID_HANDLE, None, None)
        err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
        self.vix.Vix_ReleaseHandle(self.jobHandle);
        
        if err != Vix.VIX_OK:
            raise Exception("VixVM_RevertToSnapshot Failed")
    
    def GetRootSnapshot(self, index = 0):
        snapshotHandle = c_int()
        err = self.VixVM_GetRootSnapshot(self.vmHandle, index, byref(snapshotHandle))
        self.snapshotHandle = snapshotHandle.value
        if err != Vix.VIX_OK:
            raise Exception("VixVM_GetRootSnapshot Failed")
        
    def GetNamedSnapshot(self, name):
        snapshotHandle = c_int()
        err = self.VixVM_GetNamedSnapshot(self.vmHandle, name, byref(snapshotHandle))
        if err != VIX_OK:
            raise Exception("VixVM_GetNamedSnapshot Failed")
        self.snapshotHandle = snapshotHandle.value
    
    def GetCurrentSnapshot(self):
        snapshotHandle = c_int()
        err = self.VixVM_GetCurrentSnapshot(self.vmHandle, byref(snapshotHandle))
        if err != VIX_OK:
            raise Exception("VixVM_GetCurrentSnapshot Failed")
        self.snapshotHandle = snapshotHandle.value

    def GetNumRootSnapshots(self):
        ss_num = c_int()
        err = self.VixVM_GetNumRootSnapshots(self.vmHandle, byref(ss_num))
        if err != VIX_OK:
            raise Exception("VixVM_GetNumRootSnapshots Failed")
        return ss_num

    def Disconnect(self):
        self.vix.VixHost_Disconnect(self.hostHandle)
    
    def deletevm(self):
        try:
            self.jobHandle = self.vix.VixVM_Delete(self.vmHandle, Vix.VIX_VMDELETE_DISK_FILES, None, None);
            err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
            self.vix.Vix_ReleaseHandle(self.jobHandle);
            if err != Vix.VIX_OK:
                logging.error("VixVM_delete Failed")
            return True
        except Exception, e:
            logging.error(e)
        return False
    
    def loginvm(self):
        try:
            self.jobHandle = self.vix.VixVM_WaitForToolsInGuest(self.vmHandle, Vix.TOOLS_TIMEOUT, None, None)
            err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
            self.vix.Vix_ReleaseHandle(self.jobHandle);
            if err != Vix.VIX_OK:
                logging.error("VixVM_WaitForToolsInGuest Failed")
                return False
            self.jobHandle = self.vix.VixVM_LoginInGuest(self.vmHandle, self.vmuser, self.vmpassword, Vix.VIX_LOGIN_IN_GUEST_REQUIRE_INTERACTIVE_ENVIRONMENT, None, None)
            err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
            self.vix.Vix_ReleaseHandle(self.jobHandle);
            if err != Vix.VIX_OK:
                logging.error("VixVM_LoginInGuest Failed")
                return False
            return True
        except Exception, e:
            logging.error(e)
        return False
    
    def logoutvm(self):
        try:
            self.jobHandle = self.vix.VixVM_LogoutFromGuest(self.vmHandle, None, None)
            err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
            self.vix.Vix_ReleaseHandle(self.jobHandle);
            if err != Vix.VIX_OK:
                logging.error("VixVM_LogoutFromGuest Failed")
                return False
            return True
        except Exception, e:
            logging.error(e)
        return False
    
    def runprograminvm(self, progfullpathinvm, argsline):
        try:
            self.jobHandle = self.vix.VixVM_RunProgramInGuest(self.vmHandle, progfullpathinvm, argsline, 0, Vix.VIX_INVALID_HANDLE, None, None)
            err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
            self.vix.Vix_ReleaseHandle(self.jobHandle);
            if err != Vix.VIX_OK:
                logging.error("VixVM_RunProgramInGuest Failed")
            return True
        except Exception, e:
            logging.error(e)
        return False


    def runscriptfileinvm(self, interpreter, scriptfile):
        '''
        功能：针对虚拟机运行脚本文件
        '''
        result = True
        try:
            sfile = open(scriptfile, "r")
            try:
                self.runscriptinvm(interpreter, "%s\n"%(string.join(sfile.readlines(), "\n")))
            except Exception, e:
                raise e
            finally:
                sfile.close()
        except Exception, e:
            logging.error(e)
            result = False
        finally:
            return result
    
    def runscriptinvm(self, interpreter, scriptext, blocking = True):
        '''
        if interpreter == None, it means we use cmd in Windows
        '''
        try:
            self.jobHandle = self.vix.VixVM_RunScriptInGuest(self.vmHandle, interpreter, scriptext, 0, Vix.VIX_INVALID_HANDLE, None, None)
            if not blocking:
                self.vix.Vix_ReleaseHandle(self.jobHandle)
                return True
            err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
            self.vix.Vix_ReleaseHandle(self.jobHandle);
            if err != Vix.VIX_OK:
                logging.error("VixVM_RunScriptInGuest Failed")
                return False
            return True
        except Exception, e:
            logging.error(e)
        return False
    
    def cphost2vm(self, localfulpath, fulpathinvm):
        try:
            self.jobHandle = self.vix.VixVM_CopyFileFromHostToGuest(self.vmHandle, localfulpath, fulpathinvm, 0, Vix.VIX_INVALID_HANDLE, None, None)
            err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
            self.vix.Vix_ReleaseHandle(self.jobHandle);
            if err != Vix.VIX_OK:
                logging.error("VixVM_CopyFileFromHostToGuest Failed")
                return False
            return True
        except Exception, e:
            logging.error(e)
        return False

    def cpvm2host(self, fulpathinvm, localfulpath):
        try:
            print fulpathinvm, localfulpath
            self.jobHandle = self.vix.VixVM_CopyFileFromGuestToHost(self.vmHandle, fulpathinvm, localfulpath, 0, Vix.VIX_INVALID_HANDLE, None, None)
            err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
            self.vix.Vix_ReleaseHandle(self.jobHandle);
            if err != Vix.VIX_OK:
                print "VixVM_CopyFileFromGuestToHost Failed"
                logging.error("VixVM_CopyFileFromGuestToHost Failed")
                return False
            return True
        except Exception, e:
            print e
            logging.error(e)
        return False

    def rmfileinvm(self, fulpathinvm):
        try:
            self.jobHandle = self.vix.VixVM_DeleteFileInGuest(self.vmHandle, fulpathinvm, None, None)
            err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
            self.vix.Vix_ReleaseHandle(self.jobHandle);
            if err != Vix.VIX_OK:
                logging.error("VixVM_DeleteFileInGuest Failed")
            return True
        except Exception, e:
            logging.error(e)
        return False
    
    def isfileinvm(self, fulpathinvm):
        try:
            self.jobHandle = self.vix.VixVM_FileExistsInGuest(self.vmHandle, fulpathinvm, None, None)
            err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
            self.vix.Vix_ReleaseHandle(self.jobHandle);
            if err != Vix.VIX_OK:
                logging.error("VixVM_FileExistsInGuest Failed")
            return True
        except Exception, e:
            logging.error(e)
        return False
    
    def renamefileinvm(self, oldfulpathinvm, newfulpathinvm):
        try:
            self.jobHandle = self.vix.VixVM_RenameFileInGuest(self.vmHandle, oldfulpathinvm, newfulpathinvm, None, None)
            err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
            self.vix.Vix_ReleaseHandle(self.jobHandle);
            if err != Vix.VIX_OK:
                logging.error("VixVM_RenameFileInGuest Failed")
            return True
        except Exception, e:
            logging.error(e)
        return False
    
    def lsdirinvm(self, fulpathinvm):
        try:
            self.jobHandle = self.vix.VixVM_ListDirectoryInGuest(self.vmHandle, fulpathinvm, None, None, None)
            err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
            self.vix.Vix_ReleaseHandle(self.jobHandle);
            print err
            if err != Vix.VIX_OK:
                logging.error("VixVM_ListDirectoryInGuest Failed")
            return True
        except Exception, e:
            logging.error(e)
        return False
    
    def mkdirinvm(self, newfulpathinvm):
        try:
            self.jobHandle = self.vix.VixVM_CreateDirectoryInGuest(self.vmHandle, newfulpathinvm, Vix.VIX_INVALID_HANDLE, None, None)
            err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
            self.vix.Vix_ReleaseHandle(self.jobHandle);
            if err != Vix.VIX_OK:
                logging.error("VixVM_CreateDirectoryInGuest Failed")
            return True
        except Exception, e:
            logging.error(e)
        return False
    
    def rmdirinvm(self, fulpathinvm):
        try:
            self.jobHandle = self.vix.VixVM_DeleteDirectoryInGuest(self.vmHandle, fulpathinvm, Vix.VIX_INVALID_HANDLE, None, None)
            err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
            self.vix.Vix_ReleaseHandle(self.jobHandle);
            if err != Vix.VIX_OK:
                logging.error("VixVM_DeleteDirectoryInGuest Failed")
            return True
        except Exception, e:
            logging.error(e)
        return False
    
    def isdirinvm(self, fulpathinvm):
        try:
            self.jobHandle = self.vix.VixVM_DirectoryExistsInGuest(self.vmHandle, fulpathinvm, None, None)
            err = self.VixJob_Wait2(self.jobHandle, Vix.VIX_PROPERTY_NONE)
            self.vix.Vix_ReleaseHandle(self.jobHandle);
            if err != Vix.VIX_OK:
                logging.error("VixVM_DirectoryExistsInGuest Failed")
                return False
            print "TEST %d"%self.jobHandle
            if self.jobHandle == Vix.VIX_PROPERTY_JOB_RESULT_GUEST_OBJECT_EXISTS:
                return True
        except Exception, e:
            logging.error(e)
        return False

'''
class VixException(Exception):
    def __init__(errorCode):
        self.errorCode = errorCode
'''
        



