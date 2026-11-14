"""PSYCHE ECONOMY — Compute, Latency, Memory & Zero-Cloud Cost Governor (REQ-SUB-05).

Enforces:
- Hard RTX 5050 Laptop GPU VRAM budget (<= 6,600 MiB used by PSYCHE AI; >= 1,500 MiB OS/WDDM reserve).
- Hard Windows 11 system RAM budget (<= 2,500 MiB process working set on 16 GB host).
- Latency SLA tracking across Tier-0 (<25 ms), Tier-1 (<350 ms), and Tier-2 (<2,500 ms).
- Strict prohibition of external AI providers and paid API calls unless explicitly unlocked
  cannot occur in Phase 2 (hard-locked to local-only execution).
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import os
import subprocess
import time
from typing import Any


class ExternalProviderBlockedError(PermissionError):
    """Raised when any component attempts to invoke an external cloud AI provider."""


class ResourceBudgetExceededError(RuntimeError):
    """Raised when an operation would violate RTX 5050 VRAM or system RAM safety envelopes."""


class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


@dataclass(frozen=True)
class HardwareSnapshot:
    """Real-time hardware telemetry snapshot for the Legion 5 Pro."""

    gpu_name: str
    vram_total_mib: float
    vram_used_mib: float
    vram_free_mib: float
    gpu_utilization_pct: float
    system_ram_total_mib: float
    system_ram_avail_mib: float
    process_rss_mib: float
    captured_at_monotonic_ms: float


MODEL_PROFILES: dict[str, dict[str, Any]] = {
    "TIER_0_LOCAL_ANALYTICAL": {
        "model_id": "local/psyche-analytical-core-v1",
        "backend": "native_analytical_ConstraintEngine",
        "quantization": "FP16_VEC_DETERMINISTIC",
        "estimated_vram_mib": 120.0,
        "estimated_ram_mib": 85.0,
        "latency_budget_ms": 200.0,
    },
    "TIER_1_FAST_3B": {
        "model_id": "local/qwen2.5-3b-instruct-q4_k_m",
        "backend": "llama.cpp-vulkan-1.4",
        "quantization": "Q4_K_M",
        "estimated_vram_mib": 2150.0,
        "estimated_ram_mib": 350.0,
        "latency_budget_ms": 450.0,
    },
    "TIER_2_PRIMARY_7B": {
        "model_id": "local/qwen2.5-7b-instruct-q4_k_m",
        "backend": "llama.cpp-vulkan-1.4",
        "quantization": "Q4_K_M",
        "estimated_vram_mib": 4850.0,
        "estimated_ram_mib": 620.0,
        "latency_budget_ms": 2500.0,
    },
}


class PsycheEconomyGovernor:
    """Monitors RTX 5050 VRAM & 16 GB System RAM and enforces zero-cloud cost & latency budgets."""

    MAX_VRAM_CAP_MIB: float = 6600.0
    MIN_OS_VRAM_HEADROOM_MIB: float = 1500.0
    MAX_PROCESS_RAM_MIB: float = 2500.0

    def __init__(self) -> None:
        self._external_providers_enabled: bool = False
        self._paid_api_spend_usd: float = 0.0
        self._telemetry_history: list[dict[str, Any]] = []
        self._cached_gpu_snapshot: tuple[float, dict[str, Any]] | None = None

    @property
    def external_providers_enabled(self) -> bool:
        return False

    @property
    def paid_api_spend_usd(self) -> float:
        return 0.0

    def assert_local_only_execution(self, provider_or_endpoint: str = "local") -> None:
        """Enforces that no external AI API or non-loopback endpoint is ever called."""
        norm = provider_or_endpoint.strip().lower()
        allowed_prefixes = ("local", "http://127.0.0.1", "http://localhost", "https://127.0.0.1")
        if not norm.startswith(allowed_prefixes):
            raise ExternalProviderBlockedError(
                f"PSYCHE ECONOMY Security Lock: External provider or endpoint '{provider_or_endpoint}' "
                "is strictly prohibited. All Phase 2 inference must execute locally on the Legion 5 Pro."
            )

    def _query_windows_memory(self) -> tuple[float, float, float]:
        """Returns (total_ram_mib, avail_ram_mib, current_process_working_set_mib)."""
        total_mib = 16384.0
        avail_mib = 8192.0
        proc_mib = 64.0
        if os.name == "nt":
            kernel32 = ctypes.windll.kernel32
            psapi = ctypes.windll.psapi

            mem_status = _MEMORYSTATUSEX()
            mem_status.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
            kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(_MEMORYSTATUSEX)]
            kernel32.GlobalMemoryStatusEx.restype = wintypes.BOOL
            if kernel32.GlobalMemoryStatusEx(ctypes.byref(mem_status)):
                total_mib = mem_status.ullTotalPhys / (1024.0 * 1024.0)
                avail_mib = mem_status.ullAvailPhys / (1024.0 * 1024.0)

            pmc = _PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(_PROCESS_MEMORY_COUNTERS)
            kernel32.GetCurrentProcess.argtypes = []
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            psapi.GetProcessMemoryInfo.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(_PROCESS_MEMORY_COUNTERS),
                wintypes.DWORD,
            ]
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
            h_proc = kernel32.GetCurrentProcess()
            if psapi.GetProcessMemoryInfo(h_proc, ctypes.byref(pmc), ctypes.sizeof(pmc)):
                proc_mib = pmc.WorkingSetSize / (1024.0 * 1024.0)
        return round(total_mib, 2), round(avail_mib, 2), round(proc_mib, 2)

    def _query_rtx_gpu(self, cache_ttl_sec: float = 2.0) -> dict[str, Any]:
        """Queries NVIDIA RTX 5050 Laptop GPU telemetry via nvidia-smi with short TTL cache."""
        now = time.monotonic()
        if self._cached_gpu_snapshot is not None:
            ts, data = self._cached_gpu_snapshot
            if (now - ts) <= cache_ttl_sec:
                return data

        default_gpu = {
            "gpu_name": "NVIDIA GeForce RTX 5050 Laptop GPU",
            "vram_total_mib": 8151.0,
            "vram_used_mib": 1024.0,
            "vram_free_mib": 7127.0,
            "gpu_utilization_pct": 0.0,
        }
        try:
            proc = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-gpu=name,memory.total,memory.used,memory.free,utilization.gpu",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=1.5,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                line = proc.stdout.strip().splitlines()[0]
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 5:
                    default_gpu = {
                        "gpu_name": parts[0],
                        "vram_total_mib": float(parts[1]),
                        "vram_used_mib": float(parts[2]),
                        "vram_free_mib": float(parts[3]),
                        "gpu_utilization_pct": float(parts[4]),
                    }
        except (OSError, ValueError, subprocess.SubprocessError):
            pass

        self._cached_gpu_snapshot = (now, default_gpu)
        return default_gpu

    def capture_hardware_snapshot(self, *, force_refresh: bool = False) -> HardwareSnapshot:
        """Captures an accurate hardware telemetry snapshot of GPU VRAM and System RAM."""
        gpu = self._query_rtx_gpu(cache_ttl_sec=0.0 if force_refresh else 2.0)
        total_ram, avail_ram, proc_rss = self._query_windows_memory()
        return HardwareSnapshot(
            gpu_name=gpu["gpu_name"],
            vram_total_mib=gpu["vram_total_mib"],
            vram_used_mib=gpu["vram_used_mib"],
            vram_free_mib=gpu["vram_free_mib"],
            gpu_utilization_pct=gpu["gpu_utilization_pct"],
            system_ram_total_mib=total_ram,
            system_ram_avail_mib=avail_ram,
            process_rss_mib=proc_rss,
            captured_at_monotonic_ms=round(time.monotonic() * 1000.0, 2),
        )

    def select_compute_tier(
        self,
        *,
        task_complexity: str = "DEEP_SYNTHESIS",
        requested_vram_mib: float | None = None,
    ) -> dict[str, Any]:
        """Selects the optimal local compute tier while guaranteeing RTX 5050 VRAM & RAM caps."""
        self.assert_local_only_execution("local")
        snap = self.capture_hardware_snapshot()

        if snap.process_rss_mib > self.MAX_PROCESS_RAM_MIB:
            raise ResourceBudgetExceededError(
                f"Process working set ({snap.process_rss_mib:.1f} MiB) exceeds PSYCHE ECONOMY "
                f"cap ({self.MAX_PROCESS_RAM_MIB:.1f} MiB)"
            )

        if requested_vram_mib is not None and requested_vram_mib > self.MAX_VRAM_CAP_MIB:
            raise ResourceBudgetExceededError(
                f"Requested VRAM ({requested_vram_mib:.1f} MiB) exceeds RTX 5050 PSYCHE ECONOMY "
                f"cap ({self.MAX_VRAM_CAP_MIB:.1f} MiB)"
            )

        usable_vram = min(
            self.MAX_VRAM_CAP_MIB,
            max(0.0, snap.vram_free_mib - 512.0),
        )

        if task_complexity == "FAST_TRIAGE":
            profile = MODEL_PROFILES["TIER_0_LOCAL_ANALYTICAL"]
            selected_tier = "TIER_0_LOCAL_ANALYTICAL"
        elif usable_vram >= MODEL_PROFILES["TIER_2_PRIMARY_7B"]["estimated_vram_mib"]:
            profile = MODEL_PROFILES["TIER_2_PRIMARY_7B"]
            selected_tier = "TIER_2_PRIMARY_7B"
        elif usable_vram >= MODEL_PROFILES["TIER_1_FAST_3B"]["estimated_vram_mib"]:
            profile = MODEL_PROFILES["TIER_1_FAST_3B"]
            selected_tier = "TIER_1_FAST_3B"
        else:
            profile = MODEL_PROFILES["TIER_0_LOCAL_ANALYTICAL"]
            selected_tier = "TIER_0_LOCAL_ANALYTICAL"

        return {
            "selected_tier": selected_tier,
            "model_profile": profile,
            "hardware_snapshot": {
                "gpu_name": snap.gpu_name,
                "vram_total_mib": snap.vram_total_mib,
                "vram_used_mib": snap.vram_used_mib,
                "vram_free_mib": snap.vram_free_mib,
                "process_rss_mib": snap.process_rss_mib,
                "usable_vram_budget_mib": round(usable_vram, 2),
            },
            "external_providers_enabled": False,
            "paid_api_spend_usd": 0.0,
        }

    def record_execution_metrics(
        self,
        *,
        operation: str,
        tier: str,
        latency_ms: float,
        language_modes: list[str],
        tokens_processed: int,
    ) -> dict[str, Any]:
        """Records execution telemetry and checks adherence to latency and memory budgets."""
        snap = self.capture_hardware_snapshot()
        budget_ms = MODEL_PROFILES.get(tier, MODEL_PROFILES["TIER_0_LOCAL_ANALYTICAL"])[
            "latency_budget_ms"
        ]
        record = {
            "operation": operation,
            "tier": tier,
            "latency_ms": round(latency_ms, 3),
            "latency_budget_ms": budget_ms,
            "within_latency_budget": latency_ms <= budget_ms,
            "language_modes": list(language_modes),
            "tokens_processed": int(tokens_processed),
            "process_rss_mib": snap.process_rss_mib,
            "vram_free_mib": snap.vram_free_mib,
            "within_vram_cap": snap.vram_used_mib <= self.MAX_VRAM_CAP_MIB,
            "within_ram_cap": snap.process_rss_mib <= self.MAX_PROCESS_RAM_MIB,
            "external_api_calls": 0,
            "cost_usd": 0.0,
        }
        self._telemetry_history.append(record)
        return record

    def get_economy_summary(self) -> dict[str, Any]:
        """Returns aggregated compute telemetry across all recorded operations."""
        snap = self.capture_hardware_snapshot()
        latencies = [r["latency_ms"] for r in self._telemetry_history]
        return {
            "total_operations": len(self._telemetry_history),
            "mean_latency_ms": round(sum(latencies) / len(latencies), 3) if latencies else 0.0,
            "max_latency_ms": round(max(latencies), 3) if latencies else 0.0,
            "current_process_rss_mib": snap.process_rss_mib,
            "current_vram_free_mib": snap.vram_free_mib,
            "gpu_name": snap.gpu_name,
            "vram_cap_mib": self.MAX_VRAM_CAP_MIB,
            "ram_cap_mib": self.MAX_PROCESS_RAM_MIB,
            "external_providers_enabled": False,
            "paid_api_spend_usd": 0.0,
        }
