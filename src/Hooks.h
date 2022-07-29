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

			// previously REL::ID(37673), for SE
			REL::Relocation<std::uintptr_t> ProcessHitFunc{ REL::ID(38627) };
			_IsGhost = trampoline.write_call<5>(ProcessHitFunc.address() + 0x4a8, IsGhost);

			// previously REL::ID(36715), for SE
			REL::Relocation<std::uintptr_t> NPCInvulnerableBase{ REL::ID(37725) };
			_IsGhost = trampoline.write_call<5>(NPCInvulnerableBase.address() + 0x2A, IsGhost);

			// previously REL::ID(39428), for SE
			REL::Relocation<std::uintptr_t> PCInvulnerableBase{ REL::ID(40504) };
			_IsGhost = trampoline.write_call<5>(PCInvulnerableBase.address() + 0x14, IsGhost);
		}

	private:
		static bool IsGhost(const RE::Actor* a_actor)
		{
			logger::debug("IsGhost Trigger!");

			bool iframeActive = false, iframeState = false;

			if (a_actor->GetGraphVariableBool("bIframeActive", iframeActive) && iframeActive && a_actor->GetGraphVariableBool("bInIframe", iframeState) && iframeState) {
				logger::debug("Actor is invulnerable!");
				return true;
			}

			return _IsGhost(a_actor);
		}

		static inline REL::Relocation<decltype(IsGhost)> _IsGhost;
	};
}
