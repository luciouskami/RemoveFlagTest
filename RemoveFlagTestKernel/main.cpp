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

//摘掉标志
auto RemoveThreadFlagByEthread(PETHREAD a_thread) -> NTSTATUS
{
	auto v_ret_status{ STATUS_SUCCESS };
	//PETHREAD v_thread;
	//CLIENT_ID v_cid;

	PAGED_CODE();
	//__try
	//{
	//	ProbeForRead(a_cid, sizeof(CLIENT_ID), sizeof(ULONG));
	//	v_cid = *a_cid;
	//}
	//__except (EXCEPTION_EXECUTE_HANDLER)
	//{
	//	return GetExceptionCode();
	//}
	//
	//if (nullptr != v_cid.UniqueThread)
	//{
	//	//获得ETHREAD
	//	v_ret_status = PsLookupThreadByThreadId(v_cid.UniqueThread,&v_thread);
	//	if (!NT_SUCCESS(v_ret_status))
	//	{
	//		return v_ret_status;
	//	}
		//&v_thread->CrossThreadFlags & ThreadHideFromDebugger;
		//win7 sp1 x64
#define cross_thread_flags_offest 0x448
	if (*reinterpret_cast<PULONG>(reinterpret_cast<ULONG64>(a_thread)) + cross_thread_flags_offest & ThreadHideFromDebugger)
	{
		KdPrint(("yes\n"));
		*reinterpret_cast<PULONG>(reinterpret_cast<ULONG64>(a_thread) + cross_thread_flags_offest) &= ~ThreadHideFromDebugger;

		//}
		return v_ret_status;
	}
	return v_ret_status;
}
//方法一：枚举，不是很好，至少需要从R3传入一个进程名称或者pid
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)

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
		a_ret_status = wdk::ZwQuerySystemInformation(wdk::SystemProcessInformation, v_buffer.get(), v_size, reinterpret_cast<PULONG>(&v_returned_size));
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
		VOID*        DllBase;
		VOID*        EntryPoint;
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
//方法二：使用线程回调，无需从R3传入任何数据，也直接支持复数进程，效果应该和直接SSDThook差不多
OB_PREOP_CALLBACK_STATUS preCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	auto v_thread_object_pointer = static_cast<PETHREAD>(pOperationInformation->Object);
	
	RemoveThreadFlagByEthread(v_thread_object_pointer);
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

void DriverUnload(PDRIVER_OBJECT /*a_driver_object*/)
{

	if (nullptr != g_thread_handle)
	{
		
		ObUnRegisterCallbacks(g_thread_handle);
		g_thread_handle = nullptr;
	}
	KdPrint(("Unload\n"));
}

auto DriverEntry(PDRIVER_OBJECT a_driver_object,\
	PUNICODE_STRING a_reg_path) -> NTSTATUS
{
	UNREFERENCED_PARAMETER(a_reg_path);

	//辣鸡自动部署从来没成功过。
	//KdBreakPoint();

	auto v_ret_status = STATUS_SUCCESS;
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
	BypassCheckSign(a_driver_object);
	RegisterThreadObForRemoveFlag();
	
	return v_ret_status;
}
