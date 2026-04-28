export function isVersionAffected(current: string, affectedVersions: string[] = []): boolean {
  if (affectedVersions.length === 0) return false;
  return affectedVersions.some((range) => {
    if (range.endsWith(".x")) return current.startsWith(range.replace(".x", "."));
    if (range.includes("-")) {
      const [start, end] = range.split("-").map((part) => normalize(part.trim()));
      const candidate = normalize(current);
      return compare(candidate, start) >= 0 && compare(candidate, end) <= 0;
    }
    return normalize(current) === normalize(range);
  });
}

function normalize(version: string): number[] {
  return version.replace(/[^\d.]/g, "").split(".").filter(Boolean).map(Number);
}

function compare(left: number[], right: number[]): number {
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i += 1) {
    const a = left[i] ?? 0;
    const b = right[i] ?? 0;
    if (a > b) return 1;
    if (a < b) return -1;
  }
  return 0;
}
