package artifacts

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/scanner/filetype"
	"github.com/cozygarage/sentinelflow/internal/scanner/fingerprint"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

func hardeningFindings(path, rel string, kind filetype.Kind) []api.Finding {
	switch kind {
	case filetype.KindELF:
		return elfHardening(path, rel)
	case filetype.KindPE:
		return peHardening(path, rel)
	case filetype.KindMachO:
		return machoHardening(path, rel)
	}
	return nil
}

func hardeningFinding(rel, rule, title, desc string, sev api.Severity) api.Finding {
	f := api.Finding{
		ID:          fmt.Sprintf("ART-HARD-%s-%s", rule, fingerprint.ValueHash(rel)),
		Type:        api.FindingTypeHardening,
		Severity:    sev,
		Title:       title,
		Description: desc,
		Location:    api.Location{File: rel},
		Scanner:     "artifacts",
		RuleID:      rule,
		Confidence:  0.85,
		CWE:         []string{"CWE-693"},
	}
	f.Fingerprint = fingerprint.Of(f)
	return f
}

func elfHardening(path, rel string) []api.Finding {
	ef, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer ef.Close()

	var out []api.Finding
	pie := ef.Type == elf.ET_DYN
	if !pie {
		out = append(out, hardeningFinding(rel, "elf-no-pie", "ELF is not PIE",
			"Position Independent Executable (ET_DYN) is not set; ASLR is weaker.", api.SeverityMedium))
	}

	nx := true
	for _, p := range ef.Progs {
		if p.Type == elf.PT_GNU_STACK && p.Flags&elf.PF_X != 0 {
			nx = false
		}
	}
	if !nx {
		out = append(out, hardeningFinding(rel, "elf-exec-stack", "Executable stack (NX missing)",
			"GNU_STACK is executable; NX/DEP is not in effect.", api.SeverityMedium))
	}

	relro := "none"
	bindNow := false
	for _, p := range ef.Progs {
		if p.Type == elf.PT_GNU_RELRO {
			relro = "partial"
		}
	}
	if ef.Section(".dynamic") != nil {
		ds, err := ef.DynValue(elf.DT_BIND_NOW)
		if err == nil && len(ds) > 0 {
			bindNow = true
		}
		flags, err := ef.DynValue(elf.DT_FLAGS)
		if err == nil {
			for _, f := range flags {
				if f&1 != 0 { // DF_ORIGIN is 1; DF_BIND_NOW is 0x8
					_ = f
				}
				if f&0x8 != 0 {
					bindNow = true
				}
			}
		}
		flags1, err := ef.DynValue(elf.DT_FLAGS_1)
		if err == nil {
			for _, f := range flags1 {
				if f&0x1 != 0 { // DF_1_NOW
					bindNow = true
				}
			}
		}
	}
	if relro == "partial" && bindNow {
		relro = "full"
	}
	if relro == "none" {
		out = append(out, hardeningFinding(rel, "elf-no-relro", "ELF RELRO not enabled",
			"PT_GNU_RELRO is missing; GOT overwrites are easier.", api.SeverityLow))
	} else if relro == "partial" {
		out = append(out, hardeningFinding(rel, "elf-partial-relro", "ELF has partial RELRO",
			"BIND_NOW is not set; prefer full RELRO.", api.SeverityLow))
	}

	hasCanary := false
	hasFortify := false
	hasRpath := false
	syms, _ := ef.Symbols()
	dyn, _ := ef.DynamicSymbols()
	for _, s := range append(syms, dyn...) {
		if strings.Contains(s.Name, "__stack_chk_fail") {
			hasCanary = true
		}
		if strings.Contains(s.Name, "__sprintf_chk") || strings.Contains(s.Name, "__memcpy_chk") {
			hasFortify = true
		}
	}
	if rpath, err := ef.DynString(elf.DT_RPATH); err == nil && len(rpath) > 0 {
		hasRpath = true
	}
	if runpath, err := ef.DynString(elf.DT_RUNPATH); err == nil && len(runpath) > 0 {
		hasRpath = true
	}
	if !hasCanary {
		out = append(out, hardeningFinding(rel, "elf-no-canary", "Stack canary not detected",
			"No __stack_chk_fail symbol; stack buffer overflows are unguarded.", api.SeverityLow))
	}
	if !hasFortify {
		out = append(out, hardeningFinding(rel, "elf-no-fortify", "FORTIFY_SOURCE not detected",
			"No fortified libc symbols found.", api.SeverityInfo))
	}
	if hasRpath {
		out = append(out, hardeningFinding(rel, "elf-rpath", "RPATH/RUNPATH is set",
			"Embedded RPATH/RUNPATH can be used for library injection.", api.SeverityLow))
	}
	if len(ef.Sections) > 0 {
		stripped := true
		for _, sec := range ef.Sections {
			if sec.Name == ".symtab" {
				stripped = false
				break
			}
		}
		if stripped {
			out = append(out, hardeningFinding(rel, "elf-stripped", "Symbol table stripped",
				"The binary is stripped; this is informational (good for release, harder to debug).", api.SeverityInfo))
		}
	}
	return out
}

func peHardening(path, rel string) []api.Finding {
	pf, err := pe.Open(path)
	if err != nil {
		return nil
	}
	defer pf.Close()
	var dll uint16
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dll = oh.DllCharacteristics
	case *pe.OptionalHeader64:
		dll = oh.DllCharacteristics
	default:
		return nil
	}
	const (
		dynamicBase = 0x0040
		nxCompat    = 0x0100
		guardCF     = 0x4000
	)
	var out []api.Finding
	if dll&dynamicBase == 0 {
		out = append(out, hardeningFinding(rel, "pe-no-aslr", "PE ASLR (DYNAMIC_BASE) not set",
			"Image is not relocatable; ASLR is disabled.", api.SeverityMedium))
	}
	if dll&nxCompat == 0 {
		out = append(out, hardeningFinding(rel, "pe-no-dep", "PE NX/DEP (NX_COMPAT) not set",
			"Data Execution Prevention is not enabled.", api.SeverityMedium))
	}
	if dll&guardCF == 0 {
		out = append(out, hardeningFinding(rel, "pe-no-cfg", "PE Control Flow Guard not set",
			"IMAGE_DLLCHARACTERISTICS_GUARD_CF is missing.", api.SeverityLow))
	}
	return out
}

func machoHardening(path, rel string) []api.Finding {
	mf, err := macho.Open(path)
	if err != nil {
		return nil
	}
	defer mf.Close()
	pie := false
	for _, l := range mf.Loads {
		if d, ok := l.(*macho.Dylib); ok && strings.Contains(strings.ToLower(d.Name), "pie") {
			pie = true
		}
	}
	// MH_PIE is 0x200000 in flags
	if mf.Flags&0x200000 != 0 {
		pie = true
	}
	if !pie {
		return []api.Finding{hardeningFinding(rel, "macho-no-pie", "Mach-O is not PIE",
			"MH_PIE is not set; ASLR is weaker.", api.SeverityMedium)}
	}
	return nil
}
