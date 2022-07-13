#pragma once

namespace MaxsuIFrame
{
	class IsGhostHook
	{
	public:
		static void InstallHook()
		{
			SKSE::AllocTrampoline(1 << 4);
			auto& trampoline = SKSE::GetTrampoline();

			REL::Relocation<std::uintptr_t> ProcessHitFunc{ REL::ID(38627) };
			_IsGhost = trampoline.write_call<5>(ProcessHitFunc.address() + 0x45, IsGhost);

			REL::Relocation<std::uintptr_t> NPCInvulnerableBase{ REL::ID(37725) };
			_IsGhost = trampoline.write_call<5>(NPCInvulnerableBase.address() + 0x2A, IsGhost);

			REL::Relocation<std::uintptr_t> PCInvulnerableBase{ REL::ID(40504) };
			_IsGhost = trampoline.write_call<5>(PCInvulnerableBase.address() + 0x14, IsGhost);
		}

	private:
		static bool IsGhost(const RE::Actor* a_actor)
		{
			logger::debug("IsGhost Trigger!");

			bool iframeActive = false, iframeSate = false;

			if (a_actor->GetGraphVariableBool("bIframeActive", iframeActive) && iframeActive && a_actor->GetGraphVariableBool("bInIframe", iframeSate) && iframeSate) {
				logger::debug("Actor is invulnerable!");
				return true;
			}

			return _IsGhost(a_actor);
		}

		static inline REL::Relocation<decltype(IsGhost)> _IsGhost;
	};
}