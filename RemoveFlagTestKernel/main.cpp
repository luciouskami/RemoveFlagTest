extern "C"
{

#include <ntifs.h>
#include <ntintsafe.h>
#include <ntddk.h>
#include <intrin.h>
}

#include <memory>
#include <vector>

//#include <functional> 

#include <Wdk.h>

extern "C" DRIVER_INITIALIZE DriverEntry;
#define	DEVICE_NAME			L"\\Device\\remove_flag_test"

#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#define EXE_NAME "remove_flag_test.exe"
#define EXE_NAME_U L"remove_flag_test.exe"

//work_item dpc
#define TIMER_OUT -10000 * 1000 * 5 //5秒遍历一次（复数是间隔，正数是到期）
LARGE_INTEGER g_due_time;
KDPC g_dpc;
KTIMER g_timer;
PIO_WORKITEM g_io_workitem_pointer;
PKSPIN_LOCK g_kspin_lock;
WORK_QUEUE_ITEM g_remove_item;

//一些需要复用的变量
//driver
PDRIVER_OBJECT g_driver_object{ nullptr };
PDEVICE_OBJECT g_device_object{ nullptr };

bool g_is_notify_created = false;
PEPROCESS g_exe_eprocess_pointer;
HANDLE g_exe_pid;
std::vector<HANDLE> g_exe_thread_vec;

//摘掉标志
auto RemoveThreadFlagByEthread(PETHREAD a_thread) -> NTSTATUS
{
	auto v_ret_status{ STATUS_SUCCESS };
	PAGED_CODE();
	auto v_temp_flags = wdk::PsGetThreadCrossFlags(a_thread);

		if (v_temp_flags & wdk::PsThreadCrossFlagMask::PsCrossThreadFlagsHideFromDebugger)
		{
			KdPrint(("yes\n"));
			v_temp_flags &= ~wdk::PsThreadCrossFlagMask::PsCrossThreadFlagsHideFromDebugger;
		
			wdk::PsSetThreadCrossFlags(a_thread, v_temp_flags);
			return v_ret_status;
		}
	return v_ret_status;
}
//方法一：枚举，不是很好，至少需要从R3传入一个进程名称或者pid
auto EnumProcessThread(HANDLE a_process_id,std::vector<CLIENT_ID> &a_thread_vec) -> bool
{
	
	NTSTATUS a_ret_status;
	size_t v_size = 0x20000;
	size_t v_returned_size = 0;
	std::unique_ptr<uint8_t[]> v_buffer;

	a_thread_vec.clear(); 
	do
	{
		v_buffer.reset(new uint8_t[(v_size + 7) / 8 * 8]);
		a_ret_status = wdk::ZwQuerySystemInformation(wdk::SYSTEM_INFORMATION_CLASS::SystemProcessInformation, v_buffer.get(), v_size, reinterpret_cast<PULONG>(&v_returned_size));
		if (a_ret_status == STATUS_INFO_LENGTH_MISMATCH)
		{
			v_size = v_returned_size;
			
		}
		
	} while (a_ret_status == STATUS_INFO_LENGTH_MISMATCH);
	if (a_ret_status != 0)
	{
		return false;
	}
	for (size_t v_offset = 0; v_offset < v_returned_size;)
	{
		auto v_psi = reinterpret_cast<wdk::SYSTEM_PROCESS_INFORMATION*>(v_buffer.get() + v_offset);
		if (v_psi->ImageName.Buffer != nullptr)
		{
			if (v_psi->UniqueProcessId == a_process_id)
			{
				while (v_psi->NumberOfThreads > 0)
				{ 
					wdk::PSYSTEM_THREAD_INFORMATION v_pthread_info = &v_psi->Threads[--v_psi->NumberOfThreads];
					a_thread_vec.emplace_back(v_pthread_info->ClientId);
				}	
			}
		}
		if (v_psi->NextEntryOffset == 0)
		{
			break;
		}
		v_offset += v_psi->NextEntryOffset;
	}
	return true;
}
void BypassCheckSign(PDRIVER_OBJECT a_driver_object)
{
	//STRUCT FOR WIN64
	typedef struct _LDR_DATA                         			// 24 elements, 0xE0 bytes (sizeof)
	{
		struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x10 bytes (sizeof)
		struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x10 bytes (sizeof)
		struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x10 bytes (sizeof)
		void*        DllBase;
		void*        EntryPoint;
		ULONG32      SizeOfImage;
		UINT8        _PADDING0_[0x4];
		struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x10 bytes (sizeof)
		struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x10 bytes (sizeof)
		ULONG32      Flags;
	}LDR_DATA, *PLDR_DATA;
	PLDR_DATA v_ldr;
	v_ldr = static_cast<PLDR_DATA>(a_driver_object->DriverSection);
	v_ldr->Flags |= 0x20;
}

//方法二：使用线程回调，无需从R3传入任何数据，也直接支持复数进程，效果应该和直接SSDThook差不多.
OB_PREOP_CALLBACK_STATUS preCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	if (pOperationInformation->ObjectType != *PsThreadType)
	{
		return OB_PREOP_SUCCESS;
	}
	//DzACTest
	
	auto v_thread_object_pointer = static_cast<PETHREAD>(pOperationInformation->Object);
	
	auto v_process_object_pointer = PsGetThreadProcess(v_thread_object_pointer);
	if (strcmp(reinterpret_cast<char*>(wdk::PsGetProcessImageFileName(v_process_object_pointer)), EXE_NAME) == 0)
	{
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE || pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		{
			RemoveThreadFlagByEthread(v_thread_object_pointer);
		}
	}
	return OB_PREOP_SUCCESS;
}

PVOID g_thread_handle;
auto RegisterThreadObForRemoveFlag() -> NTSTATUS
{
	auto v_status{ STATUS_SUCCESS };
	OB_CALLBACK_REGISTRATION v_ob_reg;
	OB_OPERATION_REGISTRATION op_reg;
	memset(&v_ob_reg, 0, sizeof(v_ob_reg));
	v_ob_reg.Version = ObGetFilterVersion();
	v_ob_reg.OperationRegistrationCount = 1;
	v_ob_reg.RegistrationContext = nullptr	;
	RtlInitUnicodeString(&v_ob_reg.Altitude, L"25445");
	memset(&op_reg, 0, sizeof(op_reg));
	op_reg.ObjectType = PsThreadType;
	op_reg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	op_reg.PreOperation = static_cast<POB_PRE_OPERATION_CALLBACK>(preCall);
	v_ob_reg.OperationRegistration = &op_reg;
	v_status = ObRegisterCallbacks(&v_ob_reg, &g_thread_handle);
	return v_status;
}

//使用进程和线程创建通知
void MyCreateProcessNotifyEx
(
	__inout   PEPROCESS a_process,
	__in      HANDLE a_process_id,
	__in_opt  PPS_CREATE_NOTIFY_INFO a_create_info
)
{
	auto v_status{ STATUS_SUCCESS };
	UNICODE_STRING v_temp_filename;
	//EXE_NAME_U
	BOOLEAN v_lock = FALSE;

	

	if (nullptr != a_create_info)	
	{
		v_lock = (std::wstring_view(a_create_info->ImageFileName->Buffer).find(EXE_NAME_U) != std::wstring_view::npos);
		if (v_lock)
		{
			KdPrint(("Process Create!\n"));
			g_exe_eprocess_pointer = a_process;
			g_exe_pid = a_process_id;
		}	
	}
	else
	{
		//妈呀，这里都没PPS_CREATE_NOTIFY_INFO，还用个锤子啊
		v_lock = std::string_view(reinterpret_cast<const char*>(wdk::PsGetProcessImageFileName(a_process))).find(EXE_NAME) != std::string_view::npos;
		if (v_lock)
		{
			g_exe_eprocess_pointer = nullptr;
			g_exe_pid = nullptr;
			g_exe_thread_vec.clear();
			KdPrint(("Process Exit!\n"));
		}
	}
	RtlSecureZeroMemory(&v_temp_filename, sizeof UNICODE_STRING);
}

void MyCreateThreadNotify
(
	IN HANDLE  a_process_id,
	IN HANDLE  a_thread_id,
	IN BOOLEAN  a_create
)
{
	auto v_status{ STATUS_SUCCESS };
	PEPROCESS v_eprocess_pointer;
	bool v_lock;
	if (a_create)
	{
		v_lock = a_process_id == g_exe_pid;
		if (v_lock)
		{
			KdPrint(("Thread Create!"));
			//除非使用底层API，否则在创建线程的时候不会拥有该标志
			g_exe_thread_vec.emplace_back(a_thread_id);
		}
	}
	else
	{
		v_lock = a_process_id == g_exe_pid;
		if (v_lock)
		{
			const auto it = std::find(g_exe_thread_vec.begin(), g_exe_thread_vec.end(), a_thread_id);
			g_exe_thread_vec.erase(it);
			KdPrint(("Thread Exit!"));
		}
		
	}	
}
auto CreateMonitorNotify() -> NTSTATUS
{
	auto v_ret_status{ STATUS_SUCCESS };
	v_ret_status = PsSetCreateProcessNotifyRoutineEx(static_cast<PCREATE_PROCESS_NOTIFY_ROUTINE_EX>(MyCreateProcessNotifyEx), FALSE);
	v_ret_status = PsSetCreateThreadNotifyRoutine(MyCreateThreadNotify);
	if (NT_SUCCESS(v_ret_status))
	{
		g_is_notify_created =true;
	}
	return v_ret_status;
}	
void DriverUnload(PDRIVER_OBJECT /*a_driver_object*/)
{
	KeCancelTimer(&g_timer);
	if (nullptr != g_io_workitem_pointer)
	{
		IoFreeWorkItem(g_io_workitem_pointer);
	}
	IoDeleteDevice(g_driver_object->DeviceObject);
	if (nullptr != g_thread_handle)
	{
		
		ObUnRegisterCallbacks(g_thread_handle);
		g_thread_handle = nullptr;
	}
	if (g_is_notify_created)
	{
		PsSetCreateProcessNotifyRoutineEx(static_cast<PCREATE_PROCESS_NOTIFY_ROUTINE_EX>(MyCreateProcessNotifyEx), TRUE);
		PsRemoveCreateThreadNotifyRoutine(&MyCreateThreadNotify);
	}
	KdPrint(("Unload\n"));
}
void RemoveFlagWorkItem(IN PDEVICE_OBJECT  device_object, IN PVOID  context)
{
	//KdPrint(("On RemoveFlagWorkItem!\n"));
	for (auto& v:g_exe_thread_vec)
	{
		PETHREAD v_temp_ethread_pointer;
		PsLookupThreadByThreadId(v, &v_temp_ethread_pointer);
		RemoveThreadFlagByEthread(v_temp_ethread_pointer);
	}
}
void CustomDpc(IN struct _KDPC *a_dpc, IN PVOID   /*a_context*/, IN PVOID /*a_arg1*/, IN PVOID /*a_arg2*/)
                         
{
	//KdPrint(("On CustomDpc!\n"));
	//KIRQL v_old_irql;
	//初始化work_item
	g_io_workitem_pointer = IoAllocateWorkItem(g_device_object);
	//KeAcquireSpinLock(g_kspin_lock, &v_old_irql);
	if (nullptr != g_io_workitem_pointer)
	{
		IoInitializeWorkItem(g_device_object, g_io_workitem_pointer);
		IoQueueWorkItem(g_io_workitem_pointer, static_cast<PIO_WORKITEM_ROUTINE>(RemoveFlagWorkItem), DelayedWorkQueue, nullptr);		
	}
	KeSetTimer(&g_timer, g_due_time, a_dpc);
	//KeReleaseSpinLock(g_kspin_lock, v_old_irql);
}
void WORK_THREAD(PVOID /*context*/)
{
	//初始化dpc
	//KdPrint(("On WORK_THREAD!\n"));
	g_due_time = RtlConvertLongToLargeInteger(TIMER_OUT);
	KeInitializeDpc(&g_dpc, static_cast<PKDEFERRED_ROUTINE>(CustomDpc), nullptr);
	KeSetTimer(&g_timer, g_due_time, &g_dpc);
	KeWaitForSingleObject(&g_timer, Executive, KernelMode, FALSE, nullptr);
}
auto DriverEntry(PDRIVER_OBJECT a_driver_object,\
	PUNICODE_STRING a_reg_path) -> NTSTATUS
{
	UNREFERENCED_PARAMETER(a_reg_path);

	//辣鸡自动部署从来没成功过。
	//KdBreakPoint();

	auto v_ret_status = STATUS_SUCCESS;
	UNICODE_STRING v_ustr_device_name;
	PDEVICE_OBJECT v_device_object;

	RtlInitUnicodeString(&v_ustr_device_name, DEVICE_NAME);
	v_ret_status = IoCreateDevice(a_driver_object, 0, &v_ustr_device_name, FILE_DEVICE_UNKNOWN, 0, FALSE, &v_device_object);
	g_driver_object = a_driver_object;
	g_device_object = v_device_object;
	
	for (;;)
	{
		//Thanks Meesong for WDKExt
		v_ret_status = wdk::WdkInitSystem();
		if (!NT_SUCCESS(v_ret_status))
		{
			break;
		}
		
		a_driver_object->DriverUnload = DriverUnload;
		break;
	}
	KdPrint(("load\n"));
	g_exe_thread_vec.clear();
	KeInitializeTimer(&g_timer);
	BypassCheckSign(a_driver_object);
	RegisterThreadObForRemoveFlag();
	CreateMonitorNotify();
	HANDLE v_thread_handle;
	//拉一个线程起dpc
	v_ret_status = PsCreateSystemThread(&v_thread_handle, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr,
		static_cast<PKSTART_ROUTINE>(WORK_THREAD), static_cast<PVOID>(a_driver_object));
	if (!NT_SUCCESS(v_ret_status))
	{
		return v_ret_status;
	}
	ZwClose(v_thread_handle);
	return v_ret_status;
	
}
