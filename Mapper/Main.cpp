void LogBlank();

void Log(const wchar_t* msg);

namespace Driver
{
	bool Load(const wchar_t* name);
	void Unload();
}

namespace Hypervisor
{
	bool CheckPresence();
}

void HidePath(bool hide)
{
	bool hide_ok = !hide;

	if (hide) {
		LogBlank();
		Log(L"[!] NPT hide");

		// Load the hypervisor driver if not already running.
		// This must happen before CheckPresence, which needs a live hypervisor.
		if (!Driver::Load(L"Hypervisor.sys")) {
			Log(L"[-] Failed to load Hypervisor.sys");
			hide_ok = false;
		}
		else if (!Hypervisor::CheckPresence()) {
			Log(L"[-] No hypervisor present; nothing to hide");
			hide_ok = false;
			// The driver loaded but never launched; unload it.
			Driver::Unload();
		}
		else {
			Log(L"[+] hypervisor present");
		}
	}

	(void)hide_ok;
}
