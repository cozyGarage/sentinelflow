# Offline version comparator support

SC-083 makes local OSV range comparison fail closed when version ordering is not qualified. `SEMVER` ranges use `golang.org/x/mod/semver` and reject invalid SemVer inputs. `ECOSYSTEM` ranges currently accept numeric dotted releases for the explicitly supported offline ecosystems: Go, npm, PyPI, Maven, Cargo, RubyGems, Packagist and NuGet. Numeric components are compared without integer-width overflow.

Qualifier-bearing `ECOSYSTEM` versions such as `1.0rc1`, `1.0.post1`, `1.0-sp1`, `1.0.0-rc.1` and build metadata remain uncertain. Affected-range evaluation returns an explicit unsupported-ordering error so the dependency scan cannot report a clean result based on an invented order. Exact listed-version matches do not need range ordering and continue to work.

This boundary is intentionally conservative. It does not claim full PEP 440, Maven `ComparableVersion`, RubyGems, NuGet, npm or other ecosystem-native qualifier parity. Add a dedicated comparator and pinned fixtures before widening support. Unsupported OSV range types also return errors. GIT ranges are reported as unassessed under SC-084, while exact listed-version matches are still used.
